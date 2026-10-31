# AGENTS.md

## Overview

domradar is a single-binary CLI written in Go (1.24+) that checks domain name
availability via RDAP first with a legacy WHOIS (port 43) fallback, and prints
structured WHOIS/RDAP records for a given domain. It uses only the Go standard
library plus `golang.org/x/net` and `golang.org/x/text`; there are no other
runtime dependencies.

## Setup

- Requires Go 1.24+. Install from https://go.dev/dl/.
- Fetch dependencies: `go mod download`
- No environment variables, config files, or credentials are needed to build or
  test. Outbound HTTPS and TCP port 43 access are required only at runtime, not
  for the quality gate.

## Commands

- Build: `go build ./...`
- Typecheck: `go build ./...` (Go's compiler is the typechecker; `go vet` adds static analysis)
- Test: `go test ./...`
- Lint: `go vet ./...`
- Format: `gofmt -w .` (verify with `gofmt -l .` — must print nothing)
- Binary smoke test (matches CI): `go build -trimpath -ldflags="-s -w" -o domradar . && ./domradar --version`

There is no Makefile, package.json, or linter config; CI (`.github/workflows/tests.yml`)
runs only `go vet`, `go test`, and a build smoke test.

## Conventions

- **Testability seams for I/O and exit.** All network entry points are package-level
  function variables that tests replace: `checkDomainFn`, `rdapLookupFn`,
  `whoisLookupFn`, `whoisQueryFn`, `loadRDAPBootstrap`, and `osExit`. New code that
  performs network I/O, filesystem access, or process exit must route through these
  seams (or add a new package-level var) so it can be stubbed — never call
  `os.Exit` or real network code from logic under test.
- **CLI contract.** `main()` only calls `osExit(run(os.Args[1:]))`; subcommands
  (`check`, `whois`) dispatch through the switch in `run()`. Exit codes are
  documented API behavior (see README): `check` returns 0 = all available, 1 =
  any taken, 2 = unknown/invalid; `whois` returns 0 = record found, 1 = appears
  available, 2 = failure. Preserve these codes.
- **Availability is a tri-state `*bool`.** `nil` means UNKNOWN; `true` available,
  `false` taken. Human-readable results go to stdout; errors go to stderr prefixed
  with `Error: `. JSON output must go through `json.Encoder` with
  `SetIndent("", "  ")` and `SetEscapeHTML(false)`.
- **Release artifacts are Apple Silicon only.** The release workflow publishes a
  single `domradar-darwin-arm64` binary (GOOS=darwin, GOARCH=arm64, CGO off).
  Intel (`amd64`) support has been dropped — do not re-add an amd64 matrix entry,
  and the Homebrew formula must stay arm64-only.
- **Version sync.** The `version` constant at the top of `main.go` (currently
  `const version = "1.0.0"`, line ~28) is the single source of truth: it feeds
  `userAgent` and the `domradar --version` output. Before a release, bump it to
  the new value and push a matching `v`-prefixed tag (e.g. `version = "1.0.1"` +
  tag `v1.0.1`); the two must always match. Nothing else in this repo hardcodes
  the version — `README.md` and `CONTRIBUTING.md` only use example tags, and the
  release workflow derives the artifact name from the tag. The Homebrew formula's
  own `version`/`url`/`sha256` live in the separate `ernilambar/homebrew-tap` repo
  and are updated there with `bin/release-formula domradar <version>`.
- **Changelog is flatlog-validated.** `CHANGELOG.md` must follow the
  [flatlog](https://github.com/ernilambar/flatlog) format: one `# Changelog` title,
  newest-first `## X.Y.Z - YYYY-MM-DD` headers, flat bullets grouped
  `Added:` → `Changed:` → `Fixed:`, `- Initial release` only for the first release,
  lines ≤ 120 chars. Validate with `npx @nilambar/flatlog validate <version>`
  (note the `@` scope — `npx nilambar/flatlog` does not resolve) and keep the
  topmost version equal to `main.go`'s `version` constant.
- **Formatting.** `.editorconfig` mandates tabs (4-wide), LF, UTF-8, and a final
  newline. `gofmt` output is authoritative. Do not commit the root-level `domradar`
  binary (gitignored; CI builds it only as a smoke test).

## Quality Gate

Run every command below and confirm exit code 0 (and empty output where noted)
before declaring a task complete:

1. `gofmt -l .` — must print nothing (all files formatted)
2. `go vet ./...` — exit 0
3. `go test ./...` — exit 0, all tests pass
4. `go build ./...` — exit 0, compiles cleanly

Optional, only for changes affecting live lookup behavior (requires network):
smoke-test the real commands with `go run . check example.com` and
`go run . whois --json example.com` before opening a PR.
