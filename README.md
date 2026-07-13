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
```

By default, `check` only reports on the exact domain(s) you asked about —
no extra lookups, so it stays fast. Pass `--similar` if you also want
alternatives (other TLDs, common prefixes like `get`/`my`/`try`, common
suffixes like `app`/`hq`/`hub`, and hyphenated variants) checked and shown
for any domain that's taken.

### Detailed WHOIS / RDAP lookup

```bash
# Structured RDAP info (falls back to raw WHOIS if unsupported)
domradar whois example.com

# Force the legacy raw WHOIS protocol
domradar whois example.com --raw
```

### Other flags

- `--no-color` — disable ANSI colors (auto-disabled when piping output).
- `--timeout SECONDS` — network timeout per query (default: 6s).

## Notes

- Requires outbound internet access (HTTPS for RDAP, TCP port 43 for WHOIS
  fallback). If your network blocks port 43, some TLDs without RDAP support
  will show as "UNKNOWN".
- Availability detection for legacy WHOIS is heuristic (pattern matching on
  the response text) since WHOIS output format isn't standardized across
  registries — RDAP results are authoritative where available.
