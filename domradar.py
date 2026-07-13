#!/usr/bin/env python3
"""
domradar.py — CLI tool to check domain name availability and WHOIS/RDAP details.

Features
--------
- Check availability of one or more domains.
- If no TLD is given for a name, checks it against a set of popular TLDs.
- Optionally suggests similar available alternatives when a domain is taken
  (off by default for speed — enable with --similar).
- Detailed WHOIS/RDAP lookup via the `whois` subcommand.

Implementation notes
---------------------
Availability is determined primarily via RDAP (Registration Data Access
Protocol) using the IANA bootstrap registry (https://data.iana.org/rdap/dns.json).
RDAP is JSON over HTTPS and gives an unambiguous 404 for unregistered domains,
which is far more reliable than parsing legacy WHOIS text. For TLDs without
RDAP support, the tool falls back to a classic WHOIS socket query (port 43),
starting at whois.iana.org and following registry referrals, with a
best-effort text heuristic to guess availability.

No third-party dependencies are required — everything uses the standard library.
"""

from __future__ import annotations

import argparse
import concurrent.futures
from importlib.metadata import PackageNotFoundError, version
import json
import re
import socket
import sys
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

IANA_WHOIS_SERVER = "whois.iana.org"
WHOIS_PORT = 43
RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
DEFAULT_TIMEOUT = 6
USER_AGENT = "domradar/0.1 (+https://github.com/ernilambar/domradar)"

POPULAR_TLDS = ["com", "net", "org", "io", "co", "dev", "app", "ai"]

PREFIXES = ["get", "my", "the", "try", "use", "go"]
SUFFIXES = ["app", "hq", "online", "site", "web", "hub", "labs"]

NOT_FOUND_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"no match for",
        r"not found",
        r"no data found",
        r"no entries found",
        r"no object found",
        r"domain not found",
        r"status:\s*available",
        r"status:\s*free",
        r"available for registration",
        r"no matching record",
        r"is available for registration",
        r"has not been registered",
        r"domain status:\s*no object found",
    ]
]

FOUND_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"domain name:",
        r"registrar:",
        r"creation date:",
        r"registry domain id:",
        r"status:\s*active",
        r"status:\s*ok",
    ]
]

REFERRAL_RE = re.compile(
    r"(?:refer|whois server|referralserver)\s*:\s*([a-zA-Z0-9.\-]+)", re.IGNORECASE
)

# ANSI colors (disabled automatically when not a TTY, or via --no-color)
class _Colors:
    def __init__(self):
        self._enabled = True

    def _v(self, code: str) -> str:
        return code if self._enabled else ""

    @property
    def GREEN(self) -> str: return self._v("\033[92m")
    @property
    def RED(self) -> str: return self._v("\033[91m")
    @property
    def YELLOW(self) -> str: return self._v("\033[93m")
    @property
    def DIM(self) -> str: return self._v("\033[2m")
    @property
    def BOLD(self) -> str: return self._v("\033[1m")
    @property
    def RESET(self) -> str: return self._v("\033[0m")

    def disable(self):
        self._enabled = False


Colors = _Colors()


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------


@dataclass
class CheckResult:
    domain: str
    available: Optional[bool]  # True / False / None (unknown)
    method: str
    detail: str = ""


# --------------------------------------------------------------------------
# RDAP
# --------------------------------------------------------------------------

_rdap_bootstrap_cache: Optional[dict] = None
_rdap_bootstrap_lock = threading.Lock()


def load_rdap_bootstrap(timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Fetch and cache the IANA RDAP bootstrap registry (tld -> [base urls])."""
    global _rdap_bootstrap_cache
    if _rdap_bootstrap_cache is not None:
        return _rdap_bootstrap_cache
    with _rdap_bootstrap_lock:
        if _rdap_bootstrap_cache is not None:
            return _rdap_bootstrap_cache
        mapping: dict = {}
        try:
            req = urllib.request.Request(
                RDAP_BOOTSTRAP_URL, headers={"User-Agent": USER_AGENT}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.load(resp)
            for entry in data.get("services", []):
                tlds, urls = entry[0], entry[1]
                for tld in tlds:
                    mapping[tld.lower()] = urls
        except (urllib.error.URLError, json.JSONDecodeError, OSError):
            mapping = {}
        _rdap_bootstrap_cache = mapping
    return mapping


def rdap_lookup(domain: str, timeout: float = DEFAULT_TIMEOUT) -> Optional[dict]:
    """
    Perform an RDAP lookup for `domain`.

    Returns:
        {"available": bool, "data": dict|None}  on success
        None  if RDAP is not supported for this TLD or the query failed entirely
    """
    tld = domain.rsplit(".", 1)[-1].lower()
    bootstrap = load_rdap_bootstrap(timeout=timeout)
    bases = bootstrap.get(tld)
    if not bases:
        return None

    for base in bases:
        url = base.rstrip("/") + "/domain/" + domain
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "Accept": "application/rdap+json",
                    "User-Agent": USER_AGENT,
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.load(resp)
                return {"available": False, "data": data}
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"available": True, "data": None}
            continue
        except (urllib.error.URLError, json.JSONDecodeError, OSError):
            continue
    return None


def format_rdap(data: dict) -> str:
    """Pretty-print the useful bits of an RDAP domain response."""
    lines = []
    lines.append(f"Domain:     {data.get('ldhName', 'N/A')}")

    status = data.get("status")
    if status:
        lines.append(f"Status:     {', '.join(status)}")

    for ev in data.get("events", []):
        action = ev.get("eventAction", "event")
        date = ev.get("eventDate", "N/A")
        lines.append(f"{action.replace('_', ' ').capitalize():<12}{date}")

    for ent in data.get("entities", []):
        roles = ent.get("roles", [])
        name = ent.get("handle")
        vcard = ent.get("vcardArray")
        if vcard and len(vcard) > 1:
            for item in vcard[1]:
                if item and item[0] == "fn":
                    name = item[3]
                    break
        lines.append(f"Entity:     {name or 'N/A'} ({', '.join(roles) or 'unknown role'})")

    ns_list = data.get("nameservers", [])
    if ns_list:
        lines.append("Nameservers:")
        for ns in ns_list:
            lines.append(f"  - {ns.get('ldhName', 'N/A')}")

    return "\n".join(lines)


# --------------------------------------------------------------------------
# Legacy WHOIS (fallback)
# --------------------------------------------------------------------------


def whois_query(server: str, query: str, timeout: float = DEFAULT_TIMEOUT) -> str:
    with socket.create_connection((server, WHOIS_PORT), timeout=timeout) as sock:
        sock.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode(errors="replace")


def whois_lookup(
    domain: str, timeout: float = DEFAULT_TIMEOUT, max_hops: int = 3
) -> tuple[str, Optional[str]]:
    """
    Query WHOIS starting at IANA and following registry referrals.
    Returns (full_text, error_message_or_None).
    """
    server = IANA_WHOIS_SERVER
    seen = set()
    full_text = ""
    for _ in range(max_hops):
        if server in seen:
            break
        seen.add(server)
        try:
            text = whois_query(server, domain, timeout=timeout)
        except Exception as e:
            if full_text:
                return full_text, None
            return full_text, f"Error querying {server}: {e}"
        full_text += f"\n----- Response from {server} -----\n{text}"
        m = REFERRAL_RE.search(text)
        if m:
            referral = m.group(1).strip().rstrip(".")
            if referral and referral.lower() != server.lower():
                server = referral
                continue
        break
    return full_text, None


def guess_availability_from_text(text: str) -> Optional[bool]:
    if not text:
        return None
    for pat in NOT_FOUND_PATTERNS:
        if pat.search(text):
            return True
    for pat in FOUND_PATTERNS:
        if pat.search(text):
            return False
    return None


# --------------------------------------------------------------------------
# Availability check (RDAP first, WHOIS fallback)
# --------------------------------------------------------------------------

_LABEL_RE = re.compile(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$')


def _is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False
    labels = domain.split('.')
    return len(labels) >= 2 and all(_LABEL_RE.match(lbl) for lbl in labels)


def _normalize_domain(domain: str) -> str:
    domain = domain.lower().strip()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    return domain.rstrip("/").strip(".")


def check_domain(domain: str, timeout: float = DEFAULT_TIMEOUT) -> CheckResult:
    domain = _normalize_domain(domain)
    if not _is_valid_domain(domain):
        return CheckResult(domain, None, "validation", "invalid domain name")

    rdap_result = rdap_lookup(domain, timeout=timeout)
    if rdap_result is not None:
        return CheckResult(domain, rdap_result["available"], "RDAP")

    text, err = whois_lookup(domain, timeout=timeout)
    if err and not text:
        return CheckResult(domain, None, "WHOIS", err)

    avail = guess_availability_from_text(text)
    return CheckResult(domain, avail, "WHOIS (heuristic)")


# --------------------------------------------------------------------------
# Similar domain suggestions
# --------------------------------------------------------------------------


def split_domain(domain: str) -> tuple[str, Optional[str]]:
    if "." in domain:
        name, tld = domain.split(".", 1)
        return name, tld
    return domain, None


def generate_similar(name: str, tld: Optional[str], tlds_pool: Optional[list]) -> list:
    """Generate a list of plausible alternative domain candidates."""
    seen = set()
    candidates = []

    def add(n: str, t: str):
        d = f"{n}.{t}".lower()
        if d not in seen:
            seen.add(d)
            candidates.append(d)

    base_tlds = tlds_pool or POPULAR_TLDS
    main_tld = tld or "com"

    # Same name, other popular TLDs
    for t in base_tlds:
        if t != tld:
            add(name, t)

    # Prefix / suffix variations on the original (or default) TLD
    for p in PREFIXES:
        add(f"{p}{name}", main_tld)
    for s in SUFFIXES:
        add(f"{name}{s}", main_tld)

    # A couple of hyphenated variants
    add(f"get-{name}", main_tld)
    add(f"{name}-app", main_tld)
    add(f"try-{name}", main_tld)

    return candidates


def find_available_similar(
    name: str,
    tld: Optional[str],
    count: int = 5,
    tlds_pool: Optional[list] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_checks: int = 25,
) -> list:
    candidates = generate_similar(name, tld, tlds_pool)[:max_checks]
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(check_domain, d, timeout): d for d in candidates}
        for fut in concurrent.futures.as_completed(futures):
            try:
                res = fut.result()
            except Exception:
                continue
            if res.available:
                found.append(res.domain)
            if len(found) >= count:
                for f in futures:
                    f.cancel()
                break
    return found[:count]


# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------


def status_label(available: Optional[bool]) -> str:
    if available is True:
        return f"{Colors.GREEN}AVAILABLE{Colors.RESET}"
    if available is False:
        return f"{Colors.RED}TAKEN{Colors.RESET}"
    return f"{Colors.YELLOW}UNKNOWN{Colors.RESET}"


def print_result_line(res: CheckResult):
    print(f"  {res.domain:<28} {status_label(res.available):<20} "
          f"{Colors.DIM}[{res.method}]{Colors.RESET}"
          + (f" {Colors.DIM}({res.detail}){Colors.RESET}" if res.detail else ""))


# --------------------------------------------------------------------------
# Subcommands
# --------------------------------------------------------------------------


def cmd_check(args):
    tld_pool = [t.strip().lstrip(".").lower() for t in args.tld.split(",")] if args.tld else None

    for raw in args.domains:
        name, tld = split_domain(raw.lower())

        # Build the set of domains to actually check for this input
        if tld:
            targets = [f"{name}.{tld}"]
        else:
            targets = [f"{name}.{t}" for t in (tld_pool or POPULAR_TLDS)]

        print(f"\n{Colors.BOLD}{raw}{Colors.RESET}")
        if len(targets) == 1:
            results = [check_domain(targets[0], args.timeout)]
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(10, len(targets))) as ex:
                futures = [ex.submit(check_domain, d, args.timeout) for d in targets]
                results = [fut.result() for fut in futures]
        results.sort(key=lambda r: r.domain)
        for res in results:
            print_result_line(res)

        if not args.similar:
            continue

        # Offer similar-domain suggestions for every taken/unknown target
        taken_targets = [r for r in results if r.available is False]
        for res in taken_targets:
            t_name, t_tld = split_domain(res.domain)
            suggestions = find_available_similar(
                t_name,
                t_tld,
                count=args.similar_count,
                tlds_pool=tld_pool,
                timeout=args.timeout,
            )
            if suggestions:
                print(f"    {Colors.DIM}Similar available domains for {res.domain}:{Colors.RESET}")
                for s in suggestions:
                    print(f"      {Colors.GREEN}✓{Colors.RESET} {s}")
            else:
                print(f"    {Colors.DIM}No available similar domains found for {res.domain}.{Colors.RESET}")


def cmd_whois(args):
    domain = _normalize_domain(args.domain)

    if not args.raw:
        rdap_result = rdap_lookup(domain, timeout=args.timeout)
        if rdap_result is not None:
            if rdap_result["available"]:
                print(f"{Colors.GREEN}{domain} appears to be AVAILABLE (RDAP 404 — no registration data).{Colors.RESET}")
            else:
                print(f"{Colors.BOLD}RDAP record for {domain}:{Colors.RESET}\n")
                print(format_rdap(rdap_result["data"]))
            return
        print(f"{Colors.YELLOW}RDAP not available for this TLD, falling back to WHOIS...{Colors.RESET}\n")

    text, err = whois_lookup(domain, timeout=args.timeout)
    if err and not text:
        print(f"{Colors.RED}Error: {err}{Colors.RESET}")
        sys.exit(1)

    print(text.strip())
    avail = guess_availability_from_text(text)
    if avail is True:
        print(f"\n{Colors.GREEN}Heuristic: this domain looks AVAILABLE.{Colors.RESET}")
    elif avail is False:
        print(f"\n{Colors.RED}Heuristic: this domain looks TAKEN.{Colors.RESET}")
    else:
        print(f"\n{Colors.YELLOW}Heuristic: could not determine availability from this WHOIS response.{Colors.RESET}")


# --------------------------------------------------------------------------
# Argument parsing / entry point
# --------------------------------------------------------------------------


def _similar_count_type(value: str) -> int:
    n = int(value)
    if not 1 <= n <= 20:
        raise argparse.ArgumentTypeError("must be between 1 and 20")
    return n


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="domradar",
        description="Check domain name availability and inspect WHOIS/RDAP records.",
    )
    try:
        _version = version("domradar")
    except PackageNotFoundError:
        _version = "unknown"
    parser.add_argument("--version", "-V", action="version", version=f"%(prog)s {_version}")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output.")

    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="Check availability of one or more domains.")
    p_check.add_argument("domains", nargs="+", help="Domain(s) or bare name(s), e.g. example example.com")
    p_check.add_argument(
        "--tld", help="Comma-separated list of TLDs to use when a bare name is given, "
                       "e.g. --tld com,net,io (default: com,net,org,io,co,dev,app,ai)"
    )
    p_check.add_argument(
        "--similar", action="store_true",
        help="Also suggest similar available domains when a domain is taken. "
             "Off by default for speed."
    )
    p_check.add_argument(
        "--similar-count", type=_similar_count_type, default=5,
        help="Number of similar available domains to suggest if --similar is set (default: 5, max: 20)."
    )
    p_check.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT,
        help=f"Network timeout in seconds (default: {DEFAULT_TIMEOUT})."
    )
    p_check.set_defaults(func=cmd_check)

    p_whois = sub.add_parser("whois", help="Show detailed WHOIS/RDAP info for a domain.")
    p_whois.add_argument("domain", help="Domain to look up, e.g. example.com")
    p_whois.add_argument(
        "--raw", action="store_true",
        help="Force a raw legacy WHOIS text query instead of RDAP."
    )
    p_whois.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT,
        help=f"Network timeout in seconds (default: {DEFAULT_TIMEOUT})."
    )
    p_whois.set_defaults(func=cmd_whois)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.no_color or not sys.stdout.isatty():
        Colors.disable()

    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)


if __name__ == "__main__":
    main()
