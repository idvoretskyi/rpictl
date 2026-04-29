# Architecture

## Overview

`rpictl` uses a two-binary model: the laptop-side `rpictl` CLI orchestrates provisioning by uploading a small `rpictl-agent` binary to the target Pi and invoking it step-by-step over SSH.

```
laptop                            Raspberry Pi
──────                            ────────────
rpictl provision rpi3
  │
  ├─ SSH connect ──────────────► sshd
  │
  ├─ SCP upload ───────────────► /usr/local/bin/rpictl-agent
  │
  ├─ SSH exec: rpictl-agent step preflight --input='{...}'
  │                              └─ emits JSON to stdout ──► orchestrator parses
  ├─ SSH exec: rpictl-agent step system --input='{...}'
  │                              └─ emits JSON to stdout ──► orchestrator parses
  ├─ ...
  │
  └─ SSH exec: sudo cat /etc/rancher/k3s/k3s.yaml
                                 └─ kubeconfig ──────────► rewritten + saved to laptop
```

## Agent binary embedding

`rpictl-agent` (compiled for `linux/arm64`) is embedded inside the `rpictl` binary using `//go:embed agent_binary` in `internal/cli/provision.go`. This means `rpictl` ships as a single binary with no external dependencies.

The `release.yml` GitHub Actions workflow builds the agent binary first (cross-compiled to `linux/arm64`), places it at `internal/cli/agent_binary`, then runs goreleaser.

## JSON protocol

Each step is invoked as:

```
sudo rpictl-agent step <name> --input='<json>'
```

The agent writes a single JSON object to stdout:

```json
{
  "step": "memory",
  "ok": true,
  "skipped": false,
  "changed": ["zram", "swappiness"],
  "duration_ms": 1840,
  "messages": ["zram enabled at 50%", "vm.swappiness=60"]
}
```

On error, a JSON error object is written to **stderr**:

```json
{
  "step": "preflight",
  "ok": false,
  "messages": ["OS is not Debian Trixie; rpictl requires Trixie"]
}
```

The orchestrator (`internal/orchestrator/provision.go`) parses stdout, renders progress, and aborts on `ok: false`.

## Idempotency

Each step writes a marker to `/var/lib/rpictl/<step>.done` containing the SHA256 hash of its input JSON. On re-run, if the hash matches, the step returns `skipped: true` immediately without doing any work.

## Device profiles

Device profiles (`internal/config/profiles.go`) provide default tuning values for each supported Pi model:

| Profile | zram% | swappiness | gpu_mem | eviction-hard |
|---|---|---|---|---|
| `rpi3` | 50 | 60 | 16 | 100Mi |
| `rpi3b-plus` | 50 | 60 | 16 | 100Mi |
| `rpi4` | 25 | 30 | 16 | 200Mi |
| `rpi5` | 0 | 10 | 0 (skip) | 500Mi |

With `device_profile: auto` (default), the agent reads `/proc/device-tree/model` during the preflight step to detect the model. Any config value set explicitly overrides the profile default.

## Package layout

```
internal/
  cli/          cobra commands; embeds agent_binary
  config/       rpictl.yaml schema, device profiles, parsing, validation
  ssh/          SSH client, remote exec, SCP upload
  orchestrator/ provision flow, step runner, progress rendering
  agent/        agent step implementations (runs on Pi)
  kubeconfig/   fetch + rewrite k3s.yaml
  version/      ldflags version injection
cmd/
  rpictl/       laptop CLI entrypoint
  rpictl-agent/ Pi agent entrypoint
```
