# rpictl

Provisioning CLI for Raspberry Pi single-node k3s clusters.

`rpictl provision rpi3` — that's all it takes to go from a fresh RPi OS Lite image to a working k3s cluster with kubeconfig on your laptop.

## Supported devices

| Device | Profile | Tested in v0.1.0 |
|---|---|---|
| Raspberry Pi 3B | `rpi3` | Yes |
| Raspberry Pi 3B+ | `rpi3b-plus` | Yes |
| Raspberry Pi 4 | `rpi4` | No (best-effort defaults) |
| Raspberry Pi 5 | `rpi5` | No (best-effort defaults) |

OS requirement: **Raspberry Pi OS Lite, Debian 13 Trixie**, aarch64.

## Install

```bash
brew install idvoretskyi/tap/rpictl
```

Or build from source:

```bash
go install github.com/idvoretskyi/rpictl/cmd/rpictl@latest
```

## Quickstart

1. Flash RPi OS Lite (Trixie) to SD card, enable SSH, boot the Pi.

2. Create `rpictl.yaml` in your working directory:

```yaml
hosts:
  rpi3:
    address: raspberrypi.local
    user: pi
    device_profile: rpi3b-plus
    kubeconfig:
      output: ~/.kube/rpi3.yaml
      context: rpi3
```

3. Provision:

```bash
rpictl provision rpi3
```

4. Use your cluster:

```bash
export KUBECONFIG=~/.kube/rpi3.yaml
kubectl get nodes
```

## What it does

`rpictl provision` uploads a small agent binary (`rpictl-agent`) to the Pi via SCP, then runs these steps over SSH:

| Step | What happens |
|---|---|
| `preflight` | Verify aarch64 + Trixie + RAM ≥ 900MB; detect device model |
| `system` | `apt upgrade` + timezone + hostname |
| `hardening` | sshd config + UFW + unattended-upgrades |
| `memory` | zram + swappiness + `gpu_mem` in `/boot/firmware/config.txt` |
| `prereqs` | Install curl, ca-certificates, gnupg, jq, git |
| `k3s` | Install k3s via `get.k3s.io` |
| `kubeconfig` | Fetch `/etc/rancher/k3s/k3s.yaml`, rewrite server address, write to laptop |

Each step is **idempotent** — re-running `rpictl provision` is safe.

## Commands

```
rpictl provision <host>     Run full provisioning flow
rpictl kubeconfig <host>    Fetch kubeconfig from already-provisioned host
rpictl version              Print version
```

Global flag: `--config / -c` — path to `rpictl.yaml` (default: `./rpictl.yaml`).

## Configuration reference

See [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) and [`examples/rpictl.yaml`](examples/rpictl.yaml).

## Architecture

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the orchestrator ↔ agent JSON protocol.

## Development

See [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) for build, test, and release workflow.

## What rpictl does NOT do

- Cloudflare Tunnel setup (use OpenTofu — see [idvoretskyi/ihor.xyz](https://github.com/idvoretskyi/ihor.xyz))
- Flux GitOps bootstrap
- SOPS/age secret management
- Multi-node clusters
- Any non-Raspberry-Pi hardware

## License

Apache License 2.0 — see [LICENSE](LICENSE).
