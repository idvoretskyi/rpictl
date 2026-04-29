# CLAUDE.md

Raspberry Pi provisioning CLI — single-node k3s clusters.

## Stack

- **Go 1.23+**: module at `github.com/idvoretskyi/rpictl`
- **cobra**: CLI framework (`cmd/rpictl/`)
- **golang.org/x/crypto/ssh**: SSH transport
- **go-scp**: SCP file upload
- **gopkg.in/yaml.v3**: config parsing
- **go-playground/validator**: config validation
- **log/slog**: structured logging
- **goreleaser v2**: release pipeline → GitHub Releases + Homebrew tap

## Architecture

Two binaries:
- `rpictl` — laptop-side CLI; orchestrates provisioning via SSH
- `rpictl-agent` — linux/arm64 binary; uploaded to Pi; executes steps; emits JSON

Agent is embedded in `rpictl` via `//go:embed` for single-binary distribution.

## Commands

```bash
# Build
go build ./cmd/rpictl
go build ./cmd/rpictl-agent

# Test
go test ./...

# Lint
golangci-lint run

# Release dry-run
goreleaser release --snapshot --clean
```

## Key Files

| File | Purpose |
|---|---|
| `cmd/rpictl/main.go` | Laptop CLI entrypoint |
| `cmd/rpictl-agent/main.go` | Pi agent entrypoint |
| `internal/cli/` | cobra commands (root, provision, kubeconfig, version) |
| `internal/config/` | rpictl.yaml schema, device profiles, parsing, validation |
| `internal/ssh/` | SSH client, exec, SCP upload |
| `internal/agent/` | Agent step implementations (preflight, system, hardening, memory, prereqs, k3s) |
| `internal/orchestrator/` | Provision flow, agent upload, JSON streaming, progress |
| `internal/kubeconfig/` | Fetch + rewrite k3s kubeconfig |
| `internal/version/` | ldflags version injection |
| `examples/rpictl.yaml` | Documented example config |
| `.goreleaser.yaml` | Release pipeline |
| `.github/workflows/ci.yml` | Test + lint on PR |
| `.github/workflows/release.yml` | goreleaser on tag push |

## Notes

- License: Apache 2.0
- All commits must be DCO signed-off: `git commit -s`
- Target hardware: aarch64 (RPi 3B, 3B+, 4, 5)
- Tested hardware: RPi 3B, 3B+ only (as of v0.1.0)
- OS: Raspberry Pi OS Lite, Debian 13 Trixie only
- Agent idempotency: `/var/lib/rpictl/<step>.done` markers with SHA256 of input JSON
- No Docker — k3s containerd only
- Use OpenTofu (`tofu`), not Terraform, for any infra references
