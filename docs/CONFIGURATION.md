# Configuration Reference

`rpictl` reads from `rpictl.yaml` in the current directory by default.
Override with `--config / -c`.

## Full schema

```yaml
hosts:
  <host-name>:
    # Required
    address: raspberrypi.local    # hostname or IP of the Pi
    user: pi                      # SSH user

    # Optional
    ssh_key: ~/.ssh/id_ed25519    # SSH private key; omit to use ssh-agent
    timezone: UTC                 # IANA timezone (default: UTC)
    device_profile: auto          # rpi3 | rpi3b-plus | rpi4 | rpi5 | auto

    swap:
      zram_percent: 50            # zram size as % of RAM; 0 = disabled
      swappiness: 60              # vm.swappiness value

    gpu_mem: 16                   # GPU memory split in MB (Pi 5: ignored)

    k3s:
      version: v1.31.4+k3s1      # k3s version to install
      disable:                    # components to disable
        - traefik
        - servicelb
        - metrics-server
      kubelet_args:               # extra kubelet flags (without --kubelet-arg=)
        - eviction-hard=memory.available<100Mi

    hardening:
      ssh:
        password_auth: false      # disable SSH password auth
        permit_root_login: false  # disable root SSH login
      ufw:
        enabled: true             # enable UFW firewall
        allow_ssh_from:           # restrict SSH; empty = allow from anywhere
          - 192.168.0.0/16
      unattended_upgrades: true   # enable automatic security updates

    kubeconfig:
      output: ~/.kube/rpi3.yaml   # where to write kubeconfig on laptop
      context: rpi3               # kubectl context name
```

## Device profiles

Setting `device_profile` selects built-in defaults for `swap`, `gpu_mem`, and `k3s.kubelet_args`.
Any field set explicitly in the config overrides the profile default.

| Profile | Tested | zram% | swappiness | gpu_mem | eviction-hard |
|---|---|---|---|---|---|
| `rpi3` | Yes | 50 | 60 | 16 | 100Mi |
| `rpi3b-plus` | Yes | 50 | 60 | 16 | 100Mi |
| `rpi4` | No* | 25 | 30 | 16 | 200Mi |
| `rpi5` | No* | 0 | 10 | 0 (skip) | 500Mi |
| `auto` | — | detected at runtime | | | |

*Pi 4/5 defaults are best-effort. `rpictl` will warn but proceed.

## Minimum config

```yaml
hosts:
  rpi3:
    address: raspberrypi.local
    user: pi
```

All other fields use sensible defaults.
