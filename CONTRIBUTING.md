# Contributing to domradar

Bug reports and pull requests are welcome on [GitHub](https://github.com/ernilambar/domradar).

1. Fork the repo and create your branch from `main`.
2. Make your changes and test locally with `go test ./...`.
3. Open a pull request with a clear description of what changed and why.

## Requirements

- Go 1.24+ (install from [go.dev/dl](https://go.dev/dl))
- No environment variables, config files, or credentials are needed to build or
  test. Outbound HTTPS and TCP port 43 access are only required at runtime.

## Setup

```bash
go mod download
```

## Quality gate

Run every command below and confirm exit code 0 (and empty output where noted)
before opening a pull request:

```bash
gofmt -l .        # must print nothing
go vet ./...      # static analysis
go test ./...     # all tests pass
go build ./...    # compiles cleanly
```

There is no Makefile, package.json, or linter config; CI runs `gofmt`, `go vet`,
`go test`, and a build smoke test.

## Manual Testing

Before opening a PR, verify the key commands against real domains:

```bash
go run . check example.com
go run . check --json example.com
go run . whois example.com
go run . whois --json example.com
```

## Changelog

`CHANGELOG.md` follows the [flatlog](https://github.com/ernilambar/flatlog) format:
title line, then newest-first `## X.Y.Z - YYYY-MM-DD` headers, with flat bullets
grouped `Added:` → `Changed:` → `Fixed:` (the first release uses `- Initial release`).

Add entries under an `## X.X.X - YYYY-MM-DD` placeholder block while developing, then
validate before pushing a release:

```bash
npx @nilambar/flatlog validate <version>
```

## Release

1. Bump the `version` constant at the top of `main.go` to the version being released.
2. Add the release to `CHANGELOG.md` (see below).
3. Tag and push:

Tags must be prefixed with `v` (e.g. `v0.1.2`). The release workflow triggers on `v*` tags only — an unprefixed tag like `0.1.2` will not build or publish binaries. Only the Apple Silicon `domradar-darwin-arm64` binary is published.

```bash
git tag v0.1.2
git push origin v0.1.2
```

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE).
