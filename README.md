# rpictl

[![CI](https://github.com/idvoretskyi/rpictl/actions/workflows/ci.yml/badge.svg)](https://github.com/idvoretskyi/rpictl/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/idvoretskyi/rpictl?sort=semver)](https://github.com/idvoretskyi/rpictl/releases)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/idvoretskyi/rpictl.svg)](https://pkg.go.dev/github.com/idvoretskyi/rpictl)
[![Go Report Card](https://goreportcard.com/badge/github.com/idvoretskyi/rpictl)](https://goreportcard.com/report/github.com/idvoretskyi/rpictl)

Provisioning CLI for Raspberry Pi single-node k3s clusters.

`rpictl provision rpi3` — that's all it takes to go from a fresh RPi OS Lite image to a working k3s cluster with kubeconfig on your laptop.

## Status

**v0.1.0-alpha — hardware-validated alpha.** Core provisioning flow is complete, CI-green, and validated end-to-end on real Raspberry Pi 3B+ hardware (full provision from blank RPi OS Lite Trixie to a `Ready` k3s node in under 5 minutes). Configuration schema and CLI flags may still change until v1.0.0.

Tested on: Raspberry Pi 3B, 3B+ (aarch64, RPi OS Lite Trixie).
Best-effort defaults for RPi 4 and 5 — contributions and test reports welcome.

## Why rpictl?

Most Pi k3s guides are long bash scripts, Ansible playbooks, or manual steps. Tools like `k3sup` get you k3s installed but leave system hardening, memory tuning, and kubeconfig wiring as manual follow-up work.

rpictl is a single compiled binary that:
- runs a complete, ordered provisioning flow (preflight → system → hardening → memory → prereqs → k3s → kubeconfig)
- is **idempotent** — safe to re-run after reboots or partial failures
- requires **no agent pre-installed** on the Pi — uploads its own agent binary via SCP
- outputs a ready-to-use kubeconfig on your laptop

It stops at "kubeconfig in your hand." GitOps, secrets, ingress, and multi-node topologies are intentional non-goals — layer your own tooling on top.

## Supported devices

| Device | Profile | Tested in v0.1.0-alpha |
|---|---|---|
| Raspberry Pi 3B | `rpi3` | Yes |
| Raspberry Pi 3B+ | `rpi3b-plus` | Yes (end-to-end validated) |
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

- Cloudflare Tunnel / ingress setup
- Flux GitOps bootstrap
- SOPS / age secret management
- Multi-node clusters
- Any non-Raspberry-Pi hardware

These are intentional non-goals. rpictl stops at "kubeconfig in your hand." Layer your own GitOps, IaC, and secrets tooling on top.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All commits must be signed-off (`git commit -s`) per the [Developer Certificate of Origin](https://developercertificate.org/).

## Security

To report a vulnerability, please use [GitHub private security advisories](https://github.com/idvoretskyi/rpictl/security/advisories/new) rather than opening a public issue. See [SECURITY.md](SECURITY.md) for details.

### Supply chain

Every GitHub release ships a per-artifact SPDX-JSON SBOM (`<artifact>.sbom.spdx.json`) generated by [syft](https://github.com/anchore/syft) via goreleaser, alongside a `checksums.txt` of all archives. Each binary's SBOM enumerates the exact Go module dependencies embedded in that build.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
