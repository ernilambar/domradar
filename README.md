# domradar

CLI tool to check domain name availability and pull detailed WHOIS/RDAP records.

Availability checks use **RDAP** (JSON over HTTPS, via the IANA bootstrap registry) whenever the TLD supports it — a clean 404 means "available." For TLDs without RDAP, it falls back to a classic WHOIS socket query (port 43), with a text heuristic.

## Requirements

- macOS on Apple Silicon (arm64) for the prebuilt binaries
- Go 1.24+ (only for building from source, on any platform Go supports)

## Install / Upgrade

**Homebrew (recommended, macOS):**

```bash
brew tap ernilambar/tap
brew trust ernilambar/tap
brew install ernilambar/tap/domradar
```

Upgrade later with:

```bash
brew update && brew upgrade domradar
```

**Prebuilt binary** — Apple Silicon only; download directly from GitHub releases:

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

# Only report AVAILABLE results (quiet mode)
domradar check --available-only example

# Read one domain per line from stdin
printf 'foo.com\nbar.io\n' | domradar check -

# Machine-readable JSON for scripting
domradar check --json example.com
```

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
--available-only  Only show AVAILABLE domains (check only)
--raw          Force raw legacy WHOIS instead of RDAP (whois only)
--json         Machine-readable JSON output
--timeout      Network timeout in seconds (default: 6)
```

## Notes

Release history is in [CHANGELOG.md](CHANGELOG.md).

- Requires outbound internet access (HTTPS for RDAP, TCP port 43 for WHOIS fallback). If your network blocks port 43, some TLDs without RDAP support will show as UNKNOWN.
- Availability detection for legacy WHOIS is heuristic since WHOIS output format isn't standardized — RDAP results are authoritative where available.
- IDNs (e.g. `münchen.de`) are punycode-encoded automatically before lookup.
- The IANA RDAP bootstrap map is cached at `~/.cache/domradar/bootstrap.json` with a 24-hour TTL.

## Contributing

Bug reports and pull requests are welcome on [GitHub](https://github.com/ernilambar/domradar).
See [CONTRIBUTING.md](CONTRIBUTING.md) for local setup, the quality gate, manual
testing, and the release process.

## License

[MIT](LICENSE) © [Nilambar Sharma](https://www.nilambar.net)
