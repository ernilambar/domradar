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
- JSON output for scripting via --json.
- Reads domains from stdin when '-' is passed to `check`.

Implementation notes
---------------------
Availability is determined primarily via RDAP (Registration Data Access
Protocol) using the IANA bootstrap registry (https://data.iana.org/rdap/dns.json).
RDAP is JSON over HTTPS and gives an unambiguous 404 for unregistered domains,
which is far more reliable than parsing legacy WHOIS text. For TLDs without
RDAP support, the tool falls back to a classic WHOIS socket query (port 43),
starting at whois.iana.org and following registry referrals, with a
best-effort text heuristic to guess availability.

The IANA bootstrap map is cached on disk (~/.cache/domradar/bootstrap.json)
with a 24-hour TTL to avoid a network round-trip on every cold start. RDAP
HTTPS connections are pooled per-host per-thread, so checking many domains
against the same registry reuses one TCP+TLS session.

No third-party dependencies are required — everything uses the standard library.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import http.client
import json
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Optional

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

IANA_WHOIS_SERVER = "whois.iana.org"
WHOIS_PORT = 43
RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
DEFAULT_TIMEOUT = 6


def _package_version() -> str:
    try:
        return version("domradar")
    except PackageNotFoundError:
        return "unknown"


USER_AGENT = f"domradar/{_package_version()} (+https://github.com/ernilambar/domradar)"

CACHE_DIR = Path.home() / ".cache" / "domradar"
BOOTSTRAP_CACHE = CACHE_DIR / "bootstrap.json"
BOOTSTRAP_TTL_SEC = 24 * 60 * 60

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

# `domain name:` is intentionally omitted — many "not found" responses echo
# the queried domain in that field, which caused false TAKEN classifications
# whenever the NOT_FOUND patterns didn't match a registry's exact phrasing.
FOUND_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
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


# ANSI colors (disabled automatically when not a TTY, or via --no-color/--json)
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
# HTTPS connection pooling (thread-local)
# --------------------------------------------------------------------------

_thread_local = threading.local()


def _https_get(url: str, headers: dict, timeout: float) -> tuple[int, bytes]:
    """
    GET `url` with a thread-local pooled HTTPSConnection.
    Returns (status, body). Reconnects transparently once on socket failure.
    """
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or ""
    port = parsed.port or 443
    key = (host, port)
    path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))

    conns = getattr(_thread_local, "conns", None)
    if conns is None:
        conns = {}
        _thread_local.conns = conns

    last_exc: Optional[BaseException] = None
    for attempt in range(2):
        conn = conns.get(key)
        if conn is None:
            conn = http.client.HTTPSConnection(host, port, timeout=timeout)
            conns[key] = conn
        try:
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
            body = resp.read()
            return resp.status, body
        except (http.client.HTTPException, ConnectionError, TimeoutError,
                socket.error, ssl.SSLError) as e:
            last_exc = e
            try:
                conn.close()
            except Exception:
                pass
            conns.pop(key, None)
    assert last_exc is not None
    raise last_exc


# --------------------------------------------------------------------------
# RDAP
# --------------------------------------------------------------------------

_rdap_bootstrap_cache: Optional[dict] = None
_rdap_bootstrap_lock = threading.Lock()


def _load_bootstrap_from_disk() -> Optional[dict]:
    try:
        stat = BOOTSTRAP_CACHE.stat()
        if time.time() - stat.st_mtime > BOOTSTRAP_TTL_SEC:
            return None
        with BOOTSTRAP_CACHE.open() as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return None


def _save_bootstrap_to_disk(mapping: dict) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = BOOTSTRAP_CACHE.with_suffix(".tmp")
        tmp.write_text(json.dumps(mapping))
        tmp.replace(BOOTSTRAP_CACHE)
    except OSError:
        pass


def _fetch_bootstrap(timeout: float) -> Optional[dict]:
    try:
        req = urllib.request.Request(
            RDAP_BOOTSTRAP_URL, headers={"User-Agent": USER_AGENT}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.load(resp)
    except (urllib.error.URLError, json.JSONDecodeError, OSError):
        return None
    mapping: dict = {}
    for entry in data.get("services", []):
        if len(entry) < 2:
            continue
        tlds, urls = entry[0], entry[1]
        for tld in tlds:
            mapping[tld.lower()] = urls
    return mapping


def load_rdap_bootstrap(timeout: float = DEFAULT_TIMEOUT) -> dict:
    """
    Fetch and cache the IANA RDAP bootstrap registry (tld -> [base urls]).
    Prefers a fresh disk cache; falls back to a network fetch. Failures
    are NOT cached in-memory, so a transient error can't disable RDAP for
    the rest of the process's lifetime.
    """
    global _rdap_bootstrap_cache
    if _rdap_bootstrap_cache is not None:
        return _rdap_bootstrap_cache
    with _rdap_bootstrap_lock:
        if _rdap_bootstrap_cache is not None:
            return _rdap_bootstrap_cache
        disk = _load_bootstrap_from_disk()
        if disk is not None:
            _rdap_bootstrap_cache = disk
            return disk
        fetched = _fetch_bootstrap(timeout)
        if fetched is None:
            return {}
        _rdap_bootstrap_cache = fetched
        _save_bootstrap_to_disk(fetched)
        return fetched


def _bootstrap_tld(domain: str, bootstrap: dict) -> Optional[str]:
    """
    Longest label-suffix of `domain` that appears in the bootstrap map.
    Handles multi-label public suffixes when the registry publishes them
    (e.g. `co.uk`), and falls back to the rightmost label otherwise.
    """
    labels = domain.lower().split(".")
    for i in range(1, len(labels)):
        candidate = ".".join(labels[i:])
        if candidate in bootstrap:
            return candidate
    return None


def rdap_lookup(domain: str, timeout: float = DEFAULT_TIMEOUT) -> Optional[dict]:
    """
    Perform an RDAP lookup for `domain`.

    Returns:
        {"available": True,  "data": None}     domain is unregistered (HTTP 404)
        {"available": False, "data": <dict>}   domain is registered (HTTP 200)
        {"available": None,  "error": str}     RDAP tried but couldn't determine
                                               (rate limit, 5xx, malformed JSON,
                                               network failure)
        None  if RDAP is not supported for this TLD
    """
    bootstrap = load_rdap_bootstrap(timeout=timeout)
    tld = _bootstrap_tld(domain, bootstrap)
    if tld is None:
        return None
    bases = bootstrap[tld]

    last_err: Optional[str] = None
    for base in bases:
        url = base.rstrip("/") + "/domain/" + domain
        try:
            status, body = _https_get(
                url,
                headers={
                    "Accept": "application/rdap+json",
                    "User-Agent": USER_AGENT,
                },
                timeout=timeout,
            )
        except Exception as e:
            last_err = f"connection error: {e}"
            continue

        if status == 200:
            try:
                data = json.loads(body.decode("utf-8", errors="replace"))
            except json.JSONDecodeError as e:
                last_err = f"malformed RDAP JSON: {e}"
                continue
            return {"available": False, "data": data}
        if status == 404:
            return {"available": True, "data": None}
        if status == 429:
            last_err = "rate limited (HTTP 429)"
            continue
        if 500 <= status < 600:
            last_err = f"server error (HTTP {status})"
            continue
        last_err = f"unexpected HTTP {status}"

    return {"available": None, "error": last_err or "no RDAP endpoint reachable"}


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
    seen: set[str] = set()
    full_text = ""
    for _ in range(max_hops):
        server_key = server.lower()
        if server_key in seen:
            break
        seen.add(server_key)
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
            if referral and referral.lower() != server_key:
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
# Domain normalization & validation
# --------------------------------------------------------------------------

_LABEL_RE = re.compile(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$')


def _is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False
    labels = domain.split('.')
    return len(labels) >= 2 and all(_LABEL_RE.match(lbl) for lbl in labels)


def _normalize_domain(domain: str) -> str:
    """
    Normalize user input to an ASCII, lower-case host.
    - Strips URL scheme, userinfo, path, query, fragment, and port.
    - Punycode-encodes IDNs (e.g. 'münchen.de' -> 'xn--mnchen-3ya.de').
    """
    if not domain:
        return ""
    d = domain.strip()
    if "://" not in d:
        d = "http://" + d
    try:
        parsed = urllib.parse.urlsplit(d)
        host = parsed.hostname or ""
    except ValueError:
        return ""
    host = host.strip(".").lower()
    if not host:
        return ""
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return host  # let _is_valid_domain reject it
    return host


def check_domain(domain: str, timeout: float = DEFAULT_TIMEOUT) -> CheckResult:
    domain = _normalize_domain(domain)
    if not _is_valid_domain(domain):
        return CheckResult(domain, None, "validation", "invalid domain name")

    rdap_result = rdap_lookup(domain, timeout=timeout)
    if rdap_result is not None:
        if rdap_result["available"] is None:
            # RDAP is supported but the endpoint failed us. Try WHOIS and
            # surface the RDAP error as detail so the user sees why.
            err = rdap_result.get("error", "RDAP failed")
            text, whois_err = whois_lookup(domain, timeout=timeout)
            if whois_err and not text:
                return CheckResult(domain, None, "RDAP", err)
            avail = guess_availability_from_text(text)
            return CheckResult(domain, avail, "WHOIS (RDAP fallback)", err)
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
    found: list[str] = []
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
                break
    return found[:count]


def batch_available_similar(
    taken_results: list,
    count: int,
    tlds_pool: Optional[list],
    timeout: float,
    max_checks_per: int = 25,
) -> dict:
    """
    Find available similar domains for many taken parents in one shared
    thread pool, so lookups run concurrently across all parents (not
    per-parent sequentially).
    """
    if not taken_results:
        return {}

    candidate_owner: dict = {}
    order: dict = {}
    for res in taken_results:
        t_name, t_tld = split_domain(res.domain)
        cands = generate_similar(t_name, t_tld, tlds_pool)[:max_checks_per]
        order[res.domain] = []
        for c in cands:
            if c not in candidate_owner:
                candidate_owner[c] = res.domain
                order[res.domain].append(c)

    results: dict = {r.domain: set() for r in taken_results}
    if not candidate_owner:
        return {r.domain: [] for r in taken_results}

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futs = {ex.submit(check_domain, cand, timeout): cand for cand in candidate_owner}
        for fut in concurrent.futures.as_completed(futs):
            try:
                res = fut.result()
            except Exception:
                continue
            if res.available:
                parent = candidate_owner[res.domain]
                if len(results[parent]) < count:
                    results[parent].add(res.domain)

    return {
        parent: [c for c in order[parent] if c in results[parent]][:count]
        for parent in results
    }


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


def _collect_input_domains(raw_args: list) -> list:
    """Expand '-' into stdin lines; keep order; drop blanks and '#' comments."""
    out: list = []
    for arg in raw_args:
        if arg == "-":
            for line in sys.stdin:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                out.append(s)
        else:
            out.append(arg)
    return out


def _exit_code_for_check(results: list) -> int:
    if any(r.available is None for r in results):
        return 2
    if all(r.available is True for r in results):
        return 0
    return 1


def cmd_check(args) -> int:
    tld_pool = [t.strip().lstrip(".").lower() for t in args.tld.split(",")] if args.tld else None
    inputs = _collect_input_domains(args.domains)
    if not inputs:
        msg = "no domains provided"
        if args.json:
            print(json.dumps({"error": msg}))
        else:
            print(f"{Colors.RED}Error: {msg}.{Colors.RESET}", file=sys.stderr)
        return 2

    groups: list = []
    all_results: list = []

    for raw in inputs:
        name, tld = split_domain(raw.lower())
        if tld:
            targets = [f"{name}.{tld}"]
        else:
            targets = [f"{name}.{t}" for t in (tld_pool or POPULAR_TLDS)]

        if len(targets) == 1:
            results = [check_domain(targets[0], args.timeout)]
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(10, len(targets))) as ex:
                futures = [ex.submit(check_domain, d, args.timeout) for d in targets]
                results = [fut.result() for fut in futures]
        results.sort(key=lambda r: r.domain)
        all_results.extend(results)
        groups.append({"input": raw, "results": results})

    similar_map: dict = {}
    if args.similar:
        taken = [r for g in groups for r in g["results"] if r.available is False]
        if taken:
            similar_map = batch_available_similar(
                taken, args.similar_count, tld_pool, args.timeout,
            )

    if args.json:
        payload = []
        for g in groups:
            entries = []
            for r in g["results"]:
                if args.available_only and r.available is not True:
                    continue
                item = {
                    "domain": r.domain,
                    "available": r.available,
                    "method": r.method,
                    "detail": r.detail,
                }
                if args.similar and r.available is False:
                    item["similar"] = similar_map.get(r.domain, [])
                entries.append(item)
            payload.append({"input": g["input"], "results": entries})
        print(json.dumps(payload, indent=2))
    else:
        for g in groups:
            visible = [
                r for r in g["results"]
                if not args.available_only or r.available is True
            ]
            has_similar_for_group = args.similar and any(
                similar_map.get(r.domain) for r in g["results"] if r.available is False
            )
            if not visible and not has_similar_for_group:
                continue
            print(f"\n{Colors.BOLD}{g['input']}{Colors.RESET}")
            for r in visible:
                print_result_line(r)
            if not args.similar:
                continue
            for res in g["results"]:
                if res.available is not False:
                    continue
                suggestions = similar_map.get(res.domain, [])
                if suggestions:
                    print(f"    {Colors.DIM}Similar available domains for {res.domain}:{Colors.RESET}")
                    for s in suggestions:
                        print(f"      {Colors.GREEN}✓{Colors.RESET} {s}")
                elif not args.available_only:
                    print(f"    {Colors.DIM}No available similar domains found for {res.domain}.{Colors.RESET}")

    return _exit_code_for_check(all_results)


def cmd_whois(args) -> int:
    domain = _normalize_domain(args.domain)
    if not _is_valid_domain(domain):
        msg = f"invalid domain name: {args.domain!r}"
        if args.json:
            print(json.dumps({"domain": args.domain, "error": msg}, indent=2))
        else:
            print(f"{Colors.RED}Error: {msg}{Colors.RESET}", file=sys.stderr)
        return 2

    if not args.raw:
        rdap_result = rdap_lookup(domain, timeout=args.timeout)
        if rdap_result is not None:
            if rdap_result["available"] is True:
                if args.json:
                    print(json.dumps({
                        "domain": domain, "available": True,
                        "method": "RDAP", "record": None,
                    }, indent=2))
                else:
                    print(f"{Colors.GREEN}{domain} appears to be AVAILABLE "
                          f"(RDAP 404 — no registration data).{Colors.RESET}")
                return 1
            if rdap_result["available"] is False:
                if args.json:
                    print(json.dumps({
                        "domain": domain, "available": False,
                        "method": "RDAP", "record": rdap_result["data"],
                    }, indent=2))
                else:
                    print(f"{Colors.BOLD}RDAP record for {domain}:{Colors.RESET}\n")
                    print(format_rdap(rdap_result["data"]))
                return 0
            # RDAP tried but errored — fall through to WHOIS.
            if not args.json:
                err = rdap_result.get("error", "unknown")
                print(f"{Colors.YELLOW}RDAP unavailable ({err}), "
                      f"falling back to WHOIS...{Colors.RESET}\n")
        elif not args.json:
            print(f"{Colors.YELLOW}RDAP not available for this TLD, "
                  f"falling back to WHOIS...{Colors.RESET}\n")

    text, err = whois_lookup(domain, timeout=args.timeout)
    if err and not text:
        if args.json:
            print(json.dumps({"domain": domain, "error": err}, indent=2))
        else:
            print(f"{Colors.RED}Error: {err}{Colors.RESET}", file=sys.stderr)
        return 2

    avail = guess_availability_from_text(text)
    if args.json:
        print(json.dumps({
            "domain": domain,
            "available": avail,
            "method": "WHOIS",
            "text": text.strip(),
        }, indent=2))
    else:
        print(text.strip())
        if avail is True:
            print(f"\n{Colors.GREEN}Heuristic: this domain looks AVAILABLE.{Colors.RESET}")
        elif avail is False:
            print(f"\n{Colors.RED}Heuristic: this domain looks TAKEN.{Colors.RESET}")
        else:
            print(f"\n{Colors.YELLOW}Heuristic: could not determine availability "
                  f"from this WHOIS response.{Colors.RESET}")

    if avail is True:
        return 1
    if avail is False:
        return 0
    return 2


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
    parser.add_argument("--version", "-V", action="version",
                        version=f"%(prog)s {_package_version()}")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output.")

    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="Check availability of one or more domains.")
    p_check.add_argument(
        "domains", nargs="+",
        help="Domain(s) or bare name(s), e.g. example example.com. "
             "Use '-' to read one domain per line from stdin.",
    )
    p_check.add_argument(
        "--tld",
        help="Comma-separated list of TLDs to use when a bare name is given, "
             "e.g. --tld com,net,io (default: com,net,org,io,co,dev,app,ai)",
    )
    p_check.add_argument(
        "--similar", action="store_true",
        help="Also suggest similar available domains when a domain is taken. "
             "Off by default for speed.",
    )
    p_check.add_argument(
        "--similar-count", type=_similar_count_type, default=5,
        help="Number of similar available domains to suggest if --similar is set "
             "(default: 5, max: 20).",
    )
    p_check.add_argument(
        "--available-only", action="store_true",
        help="Only report domains that are AVAILABLE.",
    )
    p_check.add_argument(
        "--json", action="store_true",
        help="Emit machine-readable JSON instead of formatted text.",
    )
    p_check.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT,
        help=f"Network timeout in seconds (default: {DEFAULT_TIMEOUT}).",
    )
    p_check.set_defaults(func=cmd_check)

    p_whois = sub.add_parser("whois", help="Show detailed WHOIS/RDAP info for a domain.")
    p_whois.add_argument("domain", help="Domain to look up, e.g. example.com")
    p_whois.add_argument(
        "--raw", action="store_true",
        help="Force a raw legacy WHOIS text query instead of RDAP.",
    )
    p_whois.add_argument(
        "--json", action="store_true",
        help="Emit machine-readable JSON instead of formatted text.",
    )
    p_whois.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT,
        help=f"Network timeout in seconds (default: {DEFAULT_TIMEOUT}).",
    )
    p_whois.set_defaults(func=cmd_whois)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.no_color or getattr(args, "json", False) or not sys.stdout.isatty():
        Colors.disable()

    try:
        return args.func(args) or 0
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
