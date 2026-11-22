# Install

## Requirements

- macOS 15 (Sequoia) or later on Apple Silicon (arm64) for the prebuilt binaries
- Go 1.27+ (only for building from source, on any platform Go supports)

## Homebrew (recommended, macOS)

```bash
brew tap ernilambar/tap
brew trust ernilambar/tap
brew install ernilambar/tap/domradar
```

Upgrade later with:

```bash
brew update && brew upgrade domradar
```

## Prebuilt binary

Apple Silicon only; download directly from GitHub releases:

```bash
curl -fL -o domradar https://github.com/ernilambar/domradar/releases/latest/download/domradar-darwin-arm64
xattr -d com.apple.quarantine domradar 2>/dev/null || true
chmod +x domradar
sudo mv domradar /usr/local/bin/
domradar --version
```

## From source

Requires Go 1.27+:

```bash
git clone https://github.com/ernilambar/domradar.git
cd domradar
go install .
```

The `domradar` binary is installed to `$(go env GOPATH)/bin`. Make sure that
directory is on your `PATH`.
