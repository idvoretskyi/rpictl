# Roadmap

This document captures the planned evolution of rpictl. The scope is intentionally
narrow: rpictl provisions a single-node k3s cluster on a Raspberry Pi and stops
there. Features outside that scope are non-goals regardless of version.

## v0.1.0 — Core provisioning (current)

**Status:** alpha (`v0.1.0-alpha.1`) — CI green, awaiting hardware validation on
physical Raspberry Pi 3B/3B+.

**Scope:**
- Two-binary model: `rpictl` (laptop) + `rpictl-agent` (Pi, uploaded via SCP)
- Full provisioning flow: `preflight` → `system` → `hardening` → `memory` → `prereqs` → `k3s` → `kubeconfig`
- Idempotent — safe to re-run; per-step done-markers with input hash
- Device profiles: `rpi3`, `rpi3b-plus`, `rpi4`, `rpi5`, `auto`
- Commands: `rpictl provision <host>`, `rpictl kubeconfig <host>`, `rpictl version`
- Basic hardening: sshd config, UFW, unattended-upgrades

**Path to stable:**
1. Hardware smoke-test on Pi 3B+ (`v0.1.0-alpha.1`)
2. Fix any issues found (`v0.1.0-alpha.2`, `alpha.3`, ...)
3. Release candidate (`v0.1.0-rc.1`) once no known issues
4. Stable (`v0.1.0`) — first hardware-blessed release

## v0.2.0 — Hardening profiles (planned)

**Status:** Design RFC — see issue [**#1**](https://github.com/idvoretskyi/rpictl/issues/1).
**Depends on:** v0.1.0 stable shipping first.

**Scope:**
- Opt-in hardening profile per host — `off` / `basic` / `standard` / `strict`
- Default for new hosts: `standard`
- New configuration block in `rpictl.yaml`:
  ```yaml
  hardening:
    level: standard
    ssh:
      password_auth: false
      allowed_users: [pi]
    firewall:
      rate_limit_ssh: true
      allow_ssh_from: []
    kernel:
      sysctl_hardening: true
    audit:
      auditd: true
      fail2ban: true
    services:
      disable_bluetooth: true
    filesystem:
      mount_hardening: true
    kubernetes:
      cis_benchmark: false   # strict level only
  ```
- New `rpictl unharden <host>` subcommand for full rollback
- New `harden-verify` agent step: reads back applied controls, outputs JSON report
- JSON hardening report written to `~/.local/share/rpictl/<host>-hardening-<timestamp>.json`

**Hardening layers by level:**

| Layer | basic | standard | strict |
|---|---|---|---|
| SSH hardening (sshd config, crypto, AllowUsers) | ✓ | ✓ | ✓ |
| UFW default-deny + rate-limit SSH | ✓ | ✓ | ✓ |
| Kernel sysctl hardening (kptr_restrict, rp_filter, syncookies, …) | | ✓ | ✓ |
| fail2ban (sshd jail) | | ✓ | ✓ |
| auditd (login, sudo, /etc/passwd, /etc/shadow) | | ✓ | ✓ |
| Mount hardening (nodev/nosuid/noexec on /tmp, /var/tmp, /dev/shm) | | ✓ | ✓ |
| Service trimming (bluetooth, cups, triggerhappy, ModemManager) | | ✓ | ✓ |
| Account hardening (chmod 700 home, lock unused system accounts, pwquality) | | ✓ | ✓ |
| Login banners (/etc/issue.net, /etc/motd) + journald persistence | | ✓ | ✓ |
| NTP hardening (timesyncd, Cloudflare/Google NTP) | | ✓ | ✓ |
| k3s CIS benchmark (audit log, protect-kernel-defaults, read-only-port=0) | | | ✓ |
| AppArmor enforce mode (containerd, runc, sshd) | | | ✓ |
| USB storage lockdown (blacklist usb-storage) | | | ✓ |

**Rollback:** every modified file backed up as `<file>.bak.rpictl`; `rpictl unharden`
restores all backups. sshd config validated with `sshd -t` before reload; SSH
reachability verified after reload; automatic rollback if unreachable.

**Out of scope for v0.2.0:**
- SELinux (RPi OS uses AppArmor)
- Full disk encryption (LUKS requires manual unlock, not viable for headless Pi)
- Port-knocking
- Full CIS Distribution Independent Linux Benchmark
- `kernel.modules_disabled=1` (blocks kernel updates, too risky for homelab)

## v0.3.0 — potential scope

Ideas that may land in v0.3.0, subject to v0.2.0 learnings:

- Pi 4 / Pi 5 hardware-validated hardening profiles
- AppArmor enforcement on Pi 3B+ (deferred from v0.2.0 if RAM is too tight)
- TPM2-backed secret sealing for Pi 4/5 (requires add-on board)
- `rpictl status <host>` — health and drift detection against desired config
- OpenSSF Scorecard badge

## Non-goals (all versions)

These are out of scope and will not be added:

- Multi-node k3s clusters
- Non-Raspberry-Pi hardware
- Docker (rpictl uses k3s built-in containerd exclusively)
- Ansible, cloud-init, or Packer-based provisioning
- GUI or web UI
- Windows host support (laptop side)
