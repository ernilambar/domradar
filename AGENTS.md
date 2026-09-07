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
- **Version sync.** The `version` constant at the top of `main.go` must match the
  latest release git tag (tags are `v`-prefixed, e.g. `v1.0.0`). Bump both together.
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
