# domradar

A dependency-free Python CLI to check domain availability, optionally suggest
similar available domains, and pull detailed WHOIS/RDAP records.

Availability checks use **RDAP** (JSON over HTTPS, via the IANA bootstrap
registry) whenever the TLD supports it — a clean 404 means "available."
For TLDs without RDAP, it falls back to a classic WHOIS socket query
(port 43), with a text heuristic. No third-party packages required.

## Setup

Install via [pipx](https://pipx.pypa.io) for a global `domradar` command available from any directory:

```bash
brew install pipx
pipx ensurepath
pipx install -e /path/to/domradar
```

## Usage

### Check availability

```bash
# Bare name -> checks against popular TLDs (com, net, org, io, co, dev, app, ai)
domradar check example

# Specific domain
domradar check example.com

# Multiple at once
domradar check example example.com mystartup.io

# Custom TLD list for bare names
domradar check example --tld com,net,dev

# Also suggest similar available alternatives when a domain is taken
# (off by default — enabling this adds extra lookups and is slower)
domradar check example.com --similar

# Control how many alternatives are suggested
domradar check example.com --similar --similar-count 10

# Only report AVAILABLE results (quiet mode)
domradar check example --available-only

# Read one domain per line from stdin
printf 'foo.com\nbar.io\n' | domradar check -

# Machine-readable JSON for scripting
domradar check example.com --json
```

By default, `check` only reports on the exact domain(s) you asked about —
no extra lookups, so it stays fast. Pass `--similar` if you also want
alternatives (other TLDs, common prefixes like `get`/`my`/`try`, common
suffixes like `app`/`hq`/`hub`, and hyphenated variants) checked and shown
for any domain that's taken.

#### Exit codes (check)

Meaningful exit codes make `domradar check` scriptable:

- `0` — every queried domain is AVAILABLE
- `1` — at least one queried domain is TAKEN (rest may be available)
- `2` — at least one result was UNKNOWN, or input was invalid

```bash
domradar check mystartup.io && echo "buy it"
```

### Detailed WHOIS / RDAP lookup

```bash
# Structured RDAP info (falls back to raw WHOIS if unsupported)
domradar whois example.com

# Force the legacy raw WHOIS protocol
domradar whois example.com --raw

# JSON output for scripting
domradar whois example.com --json
```

#### Exit codes (whois)

- `0` — a registration record was returned (domain is TAKEN)
- `1` — no record; domain appears AVAILABLE
- `2` — lookup failed or input was invalid

### Other flags

- `--no-color` — disable ANSI colors (auto-disabled when piping output or with `--json`).
- `--timeout SECONDS` — network timeout per query (default: 6s).

## Notes

- Requires outbound internet access (HTTPS for RDAP, TCP port 43 for WHOIS
  fallback). If your network blocks port 43, some TLDs without RDAP support
  will show as "UNKNOWN".
- Availability detection for legacy WHOIS is heuristic (pattern matching on
  the response text) since WHOIS output format isn't standardized across
  registries — RDAP results are authoritative where available.
- IDNs (e.g. `münchen.de`) are punycode-encoded automatically before lookup.
- The IANA RDAP bootstrap map is cached at `~/.cache/domradar/bootstrap.json`
  with a 24-hour TTL, so cold starts don't pay a full network round-trip.
- RDAP HTTPS connections are pooled per-host per-thread, so batch checks
  against the same registry reuse a single TCP+TLS session.
