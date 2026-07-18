# domradar

CLI tool to check domain name availability, optionally suggest similar available domains, and pull detailed WHOIS/RDAP records.

Availability checks use **RDAP** (JSON over HTTPS, via the IANA bootstrap registry) whenever the TLD supports it — a clean 404 means "available." For TLDs without RDAP, it falls back to a classic WHOIS socket query (port 43), with a text heuristic.

## Requirements

- Go 1.24+ (for building from source)

## Install / Upgrade

**macOS** — prebuilt binary (replace `arm64` with `amd64` for Intel Macs):

```bash
curl -fL -o domradar https://github.com/ernilambar/domradar/releases/latest/download/domradar-darwin-arm64
xattr -d com.apple.quarantine domradar 2>/dev/null || true
chmod +x domradar
sudo mv domradar /usr/local/bin/
domradar --version
```

**From source** (requires Go 1.24+):

```bash
git clone https://github.com/ernilambar/domradar.git
cd domradar
go install .
```

The `domradar` binary is installed to `$(go env GOPATH)/bin`. Make sure that directory is on your `PATH`.

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
domradar check --tld com,net,dev example

# Also suggest similar available alternatives when a domain is taken
# (off by default — enabling this adds extra lookups and is slower)
domradar check --similar example.com

# Control how many alternatives are suggested
domradar check --similar --similar-count 10 example.com

# Only report AVAILABLE results (quiet mode)
domradar check --available-only example

# Read one domain per line from stdin
printf 'foo.com\nbar.io\n' | domradar check -

# Machine-readable JSON for scripting
domradar check --json example.com
```

By default, `check` only reports on the exact domain(s) you asked about — no extra lookups, so it stays fast. Pass `--similar` if you also want alternatives (other TLDs, common prefixes like `get`/`my`/`try`, common suffixes like `app`/`hq`/`hub`, and hyphenated variants) checked and shown for any domain that's taken.

#### Exit codes (check)

- `0` — every queried domain is AVAILABLE
- `1` — at least one queried domain is TAKEN
- `2` — at least one result was UNKNOWN, or input was invalid

```bash
domradar check mystartup.io && echo "buy it"
```

### Detailed WHOIS / RDAP lookup

```bash
# Structured RDAP info (falls back to raw WHOIS if unsupported)
domradar whois example.com

# Force the legacy raw WHOIS protocol
domradar whois --raw example.com

# JSON output for scripting
domradar whois --json example.com
```

#### Exit codes (whois)

- `0` — a registration record was returned (domain is TAKEN)
- `1` — no record; domain appears AVAILABLE
- `2` — lookup failed or input was invalid

### Options

```
--tld          Comma-separated TLDs for bare names (check only)
--similar      Suggest similar available domains when taken (check only)
--similar-count  Number of suggestions, 1–20 (default: 5)
--available-only  Only show AVAILABLE domains (check only)
--raw          Force raw legacy WHOIS instead of RDAP (whois only)
--json         Machine-readable JSON output
--timeout      Network timeout in seconds (default: 6)
```

## Notes

- Requires outbound internet access (HTTPS for RDAP, TCP port 43 for WHOIS fallback). If your network blocks port 43, some TLDs without RDAP support will show as UNKNOWN.
- Availability detection for legacy WHOIS is heuristic since WHOIS output format isn't standardized — RDAP results are authoritative where available.
- IDNs (e.g. `münchen.de`) are punycode-encoded automatically before lookup.
- The IANA RDAP bootstrap map is cached at `~/.cache/domradar/bootstrap.json` with a 24-hour TTL.

## Contributing

Bug reports and pull requests are welcome on [GitHub](https://github.com/ernilambar/domradar).

1. Fork the repo and create your branch from `main`.
2. Make your changes and test locally with `go test ./...`.
3. Open a pull request with a clear description of what changed and why.

### Manual Testing

Before opening a PR, verify the key commands against real domains:

```bash
go run . check example.com
go run . check --json example.com
go run . whois example.com
go run . whois --json example.com
```

## Release

Tags must be prefixed with `v` (e.g. `v1.0.0`). The release workflow triggers on `v*` tags only — an unprefixed tag like `1.0.0` will not build or publish binaries.

```bash
git tag v1.0.0
git push origin v1.0.0
```

## License

[MIT](LICENSE)
