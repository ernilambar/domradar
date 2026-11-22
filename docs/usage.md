# Usage

Availability checks use RDAP (JSON over HTTPS, via the IANA bootstrap registry)
whenever the TLD supports it — a clean 404 means "available." For TLDs without
RDAP, domradar falls back to a classic WHOIS socket query (port 43) with a text
heuristic.

## Check availability

```bash
# Bare name -> checks against popular TLDs (com, net, org, io, co, dev, app, ai)
domradar check example

# Specific domain
domradar check example.com

# Multiple at once
domradar check example example.com mystartup.io

# Custom TLD list for bare names
domradar check --tld com,net,dev example

# Only report AVAILABLE results (quiet mode)
domradar check --available-only example

# Read one domain per line from stdin
printf 'foo.com\nbar.io\n' | domradar check -

# Machine-readable JSON for scripting
domradar check --json example.com
```

### Exit codes (check)

- `0` — every queried domain is AVAILABLE
- `1` — at least one queried domain is TAKEN
- `2` — at least one result was UNKNOWN, or input was invalid

```bash
domradar check mystartup.io && echo "buy it"
```

## Detailed WHOIS / RDAP lookup

```bash
# Structured RDAP info (falls back to raw WHOIS if unsupported)
domradar whois example.com

# Force the legacy raw WHOIS protocol
domradar whois --raw example.com

# JSON output for scripting
domradar whois --json example.com
```

### Exit codes (whois)

- `0` — a registration record was returned (domain is TAKEN)
- `1` — no record; domain appears AVAILABLE
- `2` — lookup failed or input was invalid

## Options

```
--tld          Comma-separated TLDs for bare names (check only)
--available-only  Only show AVAILABLE domains (check only)
--raw          Force raw legacy WHOIS instead of RDAP (whois only)
--json         Machine-readable JSON output
--timeout      Network timeout in seconds (default: 6)
```

## Notes

- Requires outbound internet access (HTTPS for RDAP, TCP port 43 for WHOIS
  fallback). If your network blocks port 43, some TLDs without RDAP support will
  show as UNKNOWN.
- Availability detection for legacy WHOIS is heuristic since WHOIS output format
  isn't standardized — RDAP results are authoritative where available.
- IDNs (e.g. `münchen.de`) are punycode-encoded automatically before lookup.
- The IANA RDAP bootstrap map is cached at `~/.cache/domradar/bootstrap.json`
  with a 24-hour TTL.
