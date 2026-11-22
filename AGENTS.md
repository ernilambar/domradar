# AGENTS.md

domradar is a single-binary Go (1.27+) CLI that checks domain availability via
RDAP, falling back to WHOIS (port 43), and prints structured WHOIS/RDAP records.
Dependencies: stdlib plus `golang.org/x/net` and `golang.org/x/text` only.

## Setup

Requires Go 1.27+; run `go mod download`. No env vars, config, or credentials
needed. Network access is required only at runtime, not for the quality gate.

## Conventions

- **Test seams.** Route network, filesystem, and exit operations through
  package-level vars (`checkDomainFn`, `rdapLookupFn`, `whoisLookupFn`,
  `whoisQueryFn`, `loadRDAPBootstrap`, `osExit`) so tests can stub them; never
  call `os.Exit` or real network code from logic under test.
- **CLI contract.** `main()` calls only `osExit(run(os.Args[1:]))`; `check` and
  `whois` dispatch in `run()`. Preserve exit codes: `check` 0 = all available,
  1 = any taken, 2 = unknown/invalid; `whois` 0 = record found, 1 = available,
  2 = failure.
- **Output.** Availability is a `*bool` (`nil` = UNKNOWN). Results to stdout;
  errors to stderr prefixed `Error: `. JSON via `json.Encoder` with
  `SetIndent("", "  ")` and `SetEscapeHTML(false)`.
- **Changelog.** `CHANGELOG.md` follows flatlog: newest-first
  `## X.Y.Z - YYYY-MM-DD`, bullets grouped Added/Changed/Fixed, lines ≤ 120.
  Validate with `npx @nilambar/flatlog validate <version>` (scope required); the
  top version must equal `main.go`'s `version`.
- **Formatting.** Tabs (4-wide), LF, UTF-8, final newline; `gofmt` is
  authoritative. Never commit the root `domradar` binary.

## Release

Bump the version in exactly one place: the `const version` at the top of
`main.go`. Everything else derives from it or must be kept in sync:

1. Set `const version = "X.Y.Z"` in `main.go` (single source of truth).
2. Add the top `## X.Y.Z - YYYY-MM-DD` entry to `CHANGELOG.md`; it must match
   `main.go`'s version. Validate with `npx @nilambar/flatlog validate X.Y.Z`.
3. Create tag `vX.Y.Z` (prefix required; the workflow triggers on `v*` only).
4. The release workflow publishes only `domradar-darwin-arm64` (macOS 15+,
   CGO off), built with `-ldflags="-s -w -macos 15.0"`. Never add amd64.
5. Update the Homebrew formula after the GitHub release; keep it arm64-only
   with a macOS 15 minimum.

## Quality Gate

`gofmt -l .` (must be empty), `go vet ./...`, `go test ./...`, `go build ./...`
— all exit 0. For live-lookup changes, optionally smoke-test
`go run . check example.com` and `go run . whois --json example.com`.
