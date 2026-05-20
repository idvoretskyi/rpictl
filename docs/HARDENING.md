# Hardening

rpictl applies system hardening to the Pi in 12 discrete, idempotent layers.
Each layer is gated behind a **level** preset, and every individual option can
be overridden in `rpictl.yaml`.

## Levels

| Level | Layers applied | Default for |
|---|---|---|
| `off` | none (legacy sshd config only) | — |
| `basic` | 1–2 + unattended-upgrades | rpi3, rpi3b-plus |
| `standard` | 1–10 | rpi4, rpi5 |
| `strict` | 1–12 | (explicit opt-in) |

Levels are **cumulative**: `standard` includes everything in `basic`; `strict`
includes everything in `standard`.

Set the level in your host config:

```yaml
hardening:
  level: standard   # off | basic | standard | strict
```

## Layers

| # | Name | Level | What it does |
|---|---|---|---|
| 1 | SSH daemon | basic+ | Disables password auth and root login; sets `MaxAuthTries 3` |
| 2 | UFW firewall | basic+ | Enables UFW; allows SSH (optionally restricted by CIDR); rate-limit SSH on standard+ |
| 3 | sysctl | standard+ | Applies CIS-recommended kernel parameters (IP forwarding, SYN cookies, ICMP redirects, etc.) via drop-in under `/etc/sysctl.d/` |
| 4 | fail2ban | standard+ | Installs and configures fail2ban for SSH with 5-minute ban |
| 5 | auditd | standard+ | Installs auditd with a lightweight ruleset (logins, privilege escalation, identity, sshd config) sized for 1 GB RAM |
| 6 | Mount hardening | standard+ | Adds `nodev,nosuid,noexec` to `/tmp`, `/var/tmp`, `/dev/shm` in `/etc/fstab` |
| 7 | Services | standard+ | Disables unnecessary services (`bluetooth` by default; optionally avahi, wifi) |
| 8 | Accounts | standard+ | Sets home directory mode 700; locks unused system accounts; enforces password quality (`minlen=14`, complexity) via `pwquality.conf`; configures sudo session timeout (5 min) and logging |
| 9 | Login banners | standard+ | Writes `/etc/issue`, `/etc/issue.net`, `/etc/motd` with a legal-notice banner |
| 10 | NTP | standard+ | Configures `timesyncd` with well-known public NTP pools |
| 11 | k3s CIS benchmark | strict | Writes `/etc/rancher/k3s/config.yaml` with CIS-required flags (`protect-kernel-defaults`, `anonymous-auth=false`, `audit-log-*`, etc.) |
| 12 | AppArmor + USB lockdown | strict | Appends `apparmor=1 security=apparmor` to `cmdline.txt`; optionally blacklists `usb-storage` module |

## Idempotency

Each layer writes a marker file to `/var/lib/rpictl/hardening-<layer>.done`
containing a SHA256 hash of the layer's input. Re-running `rpictl provision`
skips any layer whose marker hash matches the current config — no unnecessary
changes are made.

## Verify

After provisioning you can confirm all expected layers passed:

```bash
rpictl provision <host>   # re-runs are safe; prints verify report at end
```

The verify step (`harden-verify`) checks each active layer and emits a
JSON report. A non-zero exit code indicates at least one layer failed
verification.

## Unharden

To reverse all hardening layers:

```bash
rpictl unharden <host>
```

Each layer restores its pre-rpictl backup files (stored as
`<original-path>.bak.rpictl`). If no backup exists, the file is removed.

**SSH and UFW** also have a built-in auto-rollback: if the Pi becomes
unreachable after applying those layers, rpictl will attempt to restore the
previous config before exiting.

## AppArmor on rpi3 / rpi3b-plus

AppArmor is **off by default** on rpi3 and rpi3b-plus because it is untested on
those devices (limited RAM; kernel support varies). To opt in:

```yaml
hardening:
  level: strict
  kubernetes:
    apparmor_force: true
```

A reboot is required for AppArmor changes to take full effect.

## Configuration reference

All hardening fields and their defaults are documented in
[`examples/rpictl.yaml`](../examples/rpictl.yaml) and
[`docs/CONFIGURATION.md`](CONFIGURATION.md).
