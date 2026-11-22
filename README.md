# domradar

CLI tool to check domain name availability and pull detailed WHOIS/RDAP records.

Availability checks use **RDAP** (JSON over HTTPS, via the IANA bootstrap registry) whenever the TLD supports it — a clean 404 means "available." For TLDs without RDAP, it falls back to a classic WHOIS socket query (port 43), with a text heuristic.

## Requirements

- macOS 15 (Sequoia) or later on Apple Silicon (arm64) for the prebuilt binaries
- Go 1.27+ (only for building from source)

## Install

```bash
brew tap ernilambar/tap
brew trust ernilambar/tap
brew install ernilambar/tap/domradar
```

Other methods — prebuilt binary, building from source, and upgrades — are covered
in [docs/install.md](docs/install.md).

## Usage

```bash
# Check a domain (or a bare name across popular TLDs)
domradar check example.com

# Structured RDAP/WHOIS record
domradar whois example.com

# JSON output for scripting
domradar check --json example.com
```

Full command reference, options, exit codes, and behaviour notes:
[docs/usage.md](docs/usage.md). Release history: [CHANGELOG.md](CHANGELOG.md).

## Contributing

Bug reports and pull requests are welcome on [GitHub](https://github.com/ernilambar/domradar).
See [CONTRIBUTING.md](CONTRIBUTING.md) for local setup, the quality gate, manual
testing, and the release process.

## License

[MIT](LICENSE) © [Nilambar Sharma](https://www.nilambar.net)
