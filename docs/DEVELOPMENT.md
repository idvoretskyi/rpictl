# Development

## Prerequisites

- Go 1.23+
- `golangci-lint` (`brew install golangci-lint`)
- `goreleaser` v2 (`brew install goreleaser`)

## Build

```bash
# Build laptop CLI (host arch)
go build ./cmd/rpictl

# Build agent for linux/arm64 (cross-compile)
GOOS=linux GOARCH=arm64 go build -o internal/cli/agent_binary ./cmd/rpictl-agent

# Build everything
go build ./...
```

The agent binary at `internal/cli/agent_binary` is embedded into `rpictl` via `//go:embed`.
You must cross-compile the agent before building or testing `rpictl` with a real agent payload.
The placeholder `internal/cli/agent_binary` (empty file) allows `go build` to succeed for
development purposes; it will not work for actual provisioning.

## Test

```bash
go test ./...
go test -race ./...
```

## Lint

```bash
go vet ./...
golangci-lint run
```

## Release (dry-run)

```bash
# Build agent first
GOOS=linux GOARCH=arm64 go build \
  -ldflags "-s -w -X github.com/idvoretskyi/rpictl/internal/version.Version=dev" \
  -o internal/cli/agent_binary \
  ./cmd/rpictl-agent

goreleaser release --snapshot --clean
```

## Release (real)

Releases are triggered by pushing a tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The `release.yml` GitHub Actions workflow:
1. Cross-compiles `rpictl-agent` for `linux/arm64`
2. Places it at `internal/cli/agent_binary`
3. Runs `goreleaser release --clean`
4. Publishes archives + checksums to GitHub Releases
5. Writes `Formula/rpictl.rb` to `idvoretskyi/homebrew-tap`

### Required GitHub Actions secrets

| Secret | Description |
|---|---|
| `GITHUB_TOKEN` | Auto-provided by Actions; used to create GitHub Release |
| `HOMEBREW_TAP_GITHUB_TOKEN` | PAT with `repo` scope on `idvoretskyi/homebrew-tap` |

## End-to-end testing

CI does not test against real hardware. Before tagging a release:

1. Flash a fresh RPi OS Lite (Trixie) image to SD card
2. Boot the Pi, enable SSH
3. Run: `rpictl provision rpi3` with your local `rpictl.yaml`
4. Verify: `kubectl get nodes` returns the Pi node as Ready
5. Re-run `rpictl provision rpi3` and verify all steps report `skipped`

Tested hardware: Raspberry Pi 3B, 3B+ (as of v0.1.0).
