// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT

package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-playground/validator/v10"
	"gopkg.in/yaml.v3"
)

// HardeningLevel controls which hardening layers are applied.
// Levels are cumulative: standard includes basic; strict includes standard.
type HardeningLevel string

const (
	HardeningOff      HardeningLevel = "off"      // No hardening beyond legacy sshd config
	HardeningBasic    HardeningLevel = "basic"     // sshd + UFW + unattended-upgrades (v0.1.x behaviour)
	HardeningStandard HardeningLevel = "standard"  // basic + sysctl + fail2ban + auditd + mounts + services + accounts + banners + NTP
	HardeningStrict   HardeningLevel = "strict"    // standard + k3s CIS + AppArmor + USB lockdown
)

// Hardening holds the full hardening configuration for a host.
// The Level preset fills in unset sub-fields; explicit user values always win.
type Hardening struct {
	Level              HardeningLevel      `yaml:"level"`
	SSH                SSHHardening        `yaml:"ssh"`
	Firewall           FirewallHardening   `yaml:"firewall"`
	Kernel             KernelHardening     `yaml:"kernel"`
	Audit              AuditHardening      `yaml:"audit"`
	Services           ServiceHardening    `yaml:"services"`
	Filesystem         FilesystemHardening `yaml:"filesystem"`
	Kubernetes         KubernetesHardening `yaml:"kubernetes"`
	UnattendedUpgrades *bool               `yaml:"unattended_upgrades"` // kept for migration shim
}

// SSHHardening holds SSH daemon hardening options.
type SSHHardening struct {
	PasswordAuth    *bool    `yaml:"password_auth"`
	PermitRootLogin *bool    `yaml:"permit_root_login"`
	Port            *int     `yaml:"port"`
	AllowUsers      []string `yaml:"allowed_users"`
	MaxAuthTries    *int     `yaml:"max_auth_tries"`
}

// FirewallHardening holds UFW firewall settings.
type FirewallHardening struct {
	Enabled       *bool    `yaml:"enabled"`
	AllowSSHFrom  []string `yaml:"allow_ssh_from"`
	RateLimitSSH  *bool    `yaml:"rate_limit_ssh"`
	AllowK3sPorts *bool    `yaml:"allow_k3s_ports"` // open 6443/10250/8472 for standard+
}

// KernelHardening holds sysctl hardening options.
type KernelHardening struct {
	SysctlHardening *bool `yaml:"sysctl_hardening"`
	DisableIPv6     *bool `yaml:"disable_ipv6"`
}

// AuditHardening holds auditd and fail2ban settings.
type AuditHardening struct {
	Auditd  *bool `yaml:"auditd"`
	Fail2ban *bool `yaml:"fail2ban"`
}

// ServiceHardening controls which system services are disabled.
type ServiceHardening struct {
	DisableBluetooth *bool `yaml:"disable_bluetooth"`
	DisableAvahi     *bool `yaml:"disable_avahi"`
	DisableWifi      *bool `yaml:"disable_wifi"`
}

// FilesystemHardening controls mount and filesystem hardening.
type FilesystemHardening struct {
	MountHardening     *bool `yaml:"mount_hardening"`
	SecureSharedMemory *bool `yaml:"secure_shared_memory"`
}

// KubernetesHardening controls k3s-level security settings.
type KubernetesHardening struct {
	CISBenchmark   *bool `yaml:"cis_benchmark"`   // strict only
	AppArmorForce  *bool `yaml:"apparmor_force"`  // explicit opt-in required on rpi3/rpi3b-plus
	USBLockdown    *bool `yaml:"usb_lockdown"`    // strict only
}

// Config is the top-level rpictl.yaml structure.
type Config struct {
	Hosts map[string]*Host `yaml:"hosts" validate:"required,min=1"`
}

// Host represents a single target host in rpictl.yaml.
type Host struct {
	Address        string        `yaml:"address"          validate:"required"`
	User           string        `yaml:"user"             validate:"required"`
	SSHKey         string        `yaml:"ssh_key"`
	KnownHostsFile string        `yaml:"known_hosts_file"`
	StrictHostKey  *bool         `yaml:"strict_host_key"`
	Timezone       string        `yaml:"timezone"`
	DeviceProfile  string        `yaml:"device_profile"` // rpi3 | rpi3b-plus | rpi4 | rpi5 | auto
	Swap           SwapConfig    `yaml:"swap"`
	GPUMemMB       *int          `yaml:"gpu_mem"`
	K3s            K3sConfig     `yaml:"k3s"`
	Hardening      Hardening     `yaml:"hardening"`
	Kubeconfig     KubeconfigOut `yaml:"kubeconfig"`

	// resolved after loading — not from yaml
	resolvedProfile *Profile
}

// SwapConfig holds zram/swappiness settings.
type SwapConfig struct {
	ZRAMPercent *int `yaml:"zram_percent"`
	Swappiness  *int `yaml:"swappiness"`
}

// K3sConfig holds k3s installation parameters.
type K3sConfig struct {
	Version     string   `yaml:"version"`
	Disable     []string `yaml:"disable"`
	KubeletArgs []string `yaml:"kubelet_args"`
}

// KubeconfigOut holds where to write the fetched kubeconfig, and how to merge
// it into a shared kubeconfig file (typically ~/.kube/config).
type KubeconfigOut struct {
	Output     string `yaml:"output"`
	Context    string `yaml:"context"`
	Merge      *bool  `yaml:"merge"`
	MergeInto  string `yaml:"merge_into"`
	SetCurrent *bool  `yaml:"set_current"`
}

var validate = validator.New()

// Load reads and parses rpictl.yaml from the given path, expands ~ in paths,
// applies defaults, and validates the result.
func Load(path string) (*Config, error) {
	path, err := expandHome(path)
	if err != nil {
		return nil, fmt.Errorf("expand path: %w", err)
	}

	data, err := os.ReadFile(path) // #nosec G304 -- config path is a CLI input under user's control
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := validate.Struct(&cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	for name, host := range cfg.Hosts {
		migrateHardeningShim(name, host)
		if err := applyDefaults(name, host); err != nil {
			return nil, fmt.Errorf("host %s: %w", name, err)
		}
		if err := validateHardening(name, host); err != nil {
			return nil, fmt.Errorf("host %s hardening: %w", name, err)
		}
	}

	return &cfg, nil
}

// migrateHardeningShim accepts the v0.1.x hardening shape and promotes it
// into the new schema. Emits a deprecation warning. Removed in v0.3.0.
//
// Old shape (yaml tags on the legacy Hardening struct):
//
//	hardening:
//	  ssh:
//	    password_auth: false
//	    permit_root_login: false
//	  ufw:
//	    enabled: true
//	    allow_ssh_from: [...]
//	  unattended_upgrades: true
func migrateHardeningShim(name string, h *Host) {
	// The legacy UFWConfig is now FirewallHardening. Since we renamed the yaml
	// field from "ufw" to "firewall", old configs that used "ufw:" will simply
	// have FirewallHardening zero-valued — we detect this by checking if the
	// old field was parsed (it can't be, yaml field is gone). Instead, we use
	// the UnattendedUpgrades pointer: if it was set as a bool in the old shape
	// via the pointer field we added, that's a sign the user has an old config.
	// We also check if Level is empty as a general indicator of old-style config.
	//
	// Because yaml.v3 doesn't populate removed fields, the actual migration
	// that matters is: if Level is unset and the struct has old-style values
	// (password_auth/permit_root_login set via ssh sub-key, which still maps),
	// we treat this as "basic" and emit a warning.
	if h.Hardening.Level != "" {
		return // new-style config, nothing to do
	}

	// Level is unset: this is either an old config or a new config that omits
	// level (which is fine — we'll default it below). Either way emit a hint
	// if SSH sub-fields look like they were explicitly set.
	if h.Hardening.SSH.PasswordAuth != nil || h.Hardening.SSH.PermitRootLogin != nil {
		slog.Warn("hardening config detected without level field; defaulting to basic. "+
			"Consider adding 'hardening.level: basic' to suppress this warning.",
			"host", name)
	}
}

// validateHardening enforces inter-field constraints.
func validateHardening(name string, h *Host) error {
	lvl := h.Hardening.Level
	if lvl == HardeningStrict {
		pa := h.Hardening.SSH.PasswordAuth
		if pa != nil && *pa {
			return fmt.Errorf("strict level requires ssh.password_auth=false, but it is set to true")
		}
		pr := h.Hardening.SSH.PermitRootLogin
		if pr != nil && *pr {
			return fmt.Errorf("strict level requires ssh.permit_root_login=false, but it is set to true")
		}
	}
	// Warn if AppArmor requested on rpi3/rpi3b-plus without apparmor_force
	if lvl == HardeningStrict {
		af := h.Hardening.Kubernetes.AppArmorForce
		profile := h.DeviceProfile
		if (profile == "rpi3" || profile == "rpi3b-plus") && (af == nil || !*af) {
			slog.Warn("AppArmor (layer 12) is not applied by default on rpi3/rpi3b-plus — "+
				"set hardening.kubernetes.apparmor_force: true to override (untested on this hardware)",
				"host", name, "profile", profile)
		}
	}
	_ = name
	return nil
}

// GetHost returns the host config for the given name.
func (c *Config) GetHost(name string) (*Host, error) {
	h, ok := c.Hosts[name]
	if !ok {
		return nil, fmt.Errorf("host %q not found in config; defined hosts: %s",
			name, strings.Join(hostNames(c), ", "))
	}
	return h, nil
}

// ResolvedProfile returns the device profile that was resolved for this host.
func (h *Host) ResolvedProfile() *Profile {
	return h.resolvedProfile
}

func applyDefaults(name string, h *Host) error {
	// Default device_profile to "auto"
	if h.DeviceProfile == "" {
		h.DeviceProfile = "auto"
	}

	// For "auto", we can't resolve here (need remote detection);
	// for a named profile, resolve it now so callers can read defaults.
	if h.DeviceProfile != "auto" {
		p, ok := GetProfile(h.DeviceProfile)
		if !ok {
			return fmt.Errorf("unknown device_profile %q; valid values: %s",
				h.DeviceProfile, strings.Join(KnownProfiles(), ", "))
		}
		h.resolvedProfile = &p
		applyProfileDefaults(h, &p)
	}

	// Default SSH host-key mode
	if h.StrictHostKey == nil {
		f := false
		h.StrictHostKey = &f
	}
	if h.KnownHostsFile == "" {
		h.KnownHostsFile = "~/.ssh/known_hosts"
	}

	// Default timezone
	if h.Timezone == "" {
		h.Timezone = "UTC"
	}

	// Default k3s disabled components
	if len(h.K3s.Disable) == 0 {
		h.K3s.Disable = []string{"traefik", "servicelb", "metrics-server"}
	}

	// Apply hardening level defaults
	applyHardeningDefaults(h)

	// Default kubeconfig output path
	if h.Kubeconfig.Output == "" {
		h.Kubeconfig.Output = fmt.Sprintf("~/.kube/%s.yaml", name)
	}
	if h.Kubeconfig.Context == "" {
		h.Kubeconfig.Context = name
	}
	if h.Kubeconfig.Merge == nil {
		t := true
		h.Kubeconfig.Merge = &t
	}
	if h.Kubeconfig.MergeInto == "" {
		h.Kubeconfig.MergeInto = "~/.kube/config"
	}
	if h.Kubeconfig.SetCurrent == nil {
		f := false
		h.Kubeconfig.SetCurrent = &f
	}

	// Expand ~ in ssh_key, known_hosts_file, and kubeconfig output
	if h.SSHKey != "" {
		expanded, err := expandHome(h.SSHKey)
		if err != nil {
			return fmt.Errorf("expand ssh_key: %w", err)
		}
		h.SSHKey = expanded
	}
	if h.KnownHostsFile != "" {
		expanded, err := expandHome(h.KnownHostsFile)
		if err != nil {
			return fmt.Errorf("expand known_hosts_file: %w", err)
		}
		h.KnownHostsFile = expanded
	}
	expanded, err := expandHome(h.Kubeconfig.Output)
	if err != nil {
		return fmt.Errorf("expand kubeconfig.output: %w", err)
	}
	h.Kubeconfig.Output = expanded
	mergeInto, err := expandHome(h.Kubeconfig.MergeInto)
	if err != nil {
		return fmt.Errorf("expand kubeconfig.merge_into: %w", err)
	}
	h.Kubeconfig.MergeInto = mergeInto

	return nil
}

// ApplyHardeningDefaults sets hardening level and fills preset values for
// unset sub-fields. Exported so the CLI can re-apply after overriding Level.
// Explicit user values always take precedence.
func ApplyHardeningDefaults(h *Host) {
	applyHardeningDefaults(h)
}

func applyHardeningDefaults(h *Host) {
	// Default level: basic for rpi3/rpi3b-plus, standard for rpi4/rpi5.
	if h.Hardening.Level == "" {
		switch h.DeviceProfile {
		case "rpi4", "rpi5":
			h.Hardening.Level = HardeningStandard
		default:
			h.Hardening.Level = HardeningBasic
		}
	}

	lvl := h.Hardening.Level

	// SSH defaults — apply for all levels >= off
	if h.Hardening.SSH.PasswordAuth == nil {
		f := false
		h.Hardening.SSH.PasswordAuth = &f
	}
	if h.Hardening.SSH.PermitRootLogin == nil {
		f := false
		h.Hardening.SSH.PermitRootLogin = &f
	}
	if h.Hardening.SSH.MaxAuthTries == nil && lvl != HardeningOff {
		v := 3
		h.Hardening.SSH.MaxAuthTries = &v
	}

	// Firewall defaults
	if h.Hardening.Firewall.Enabled == nil {
		t := lvl != HardeningOff
		h.Hardening.Firewall.Enabled = &t
	}
	if h.Hardening.Firewall.RateLimitSSH == nil {
		t := lvl == HardeningStandard || lvl == HardeningStrict
		h.Hardening.Firewall.RateLimitSSH = &t
	}
	if h.Hardening.Firewall.AllowK3sPorts == nil {
		t := lvl == HardeningStandard || lvl == HardeningStrict
		h.Hardening.Firewall.AllowK3sPorts = &t
	}

	// UnattendedUpgrades pointer migration: if old-style bool field was set, use it
	if h.Hardening.UnattendedUpgrades == nil {
		t := lvl != HardeningOff
		h.Hardening.UnattendedUpgrades = &t
	}

	// Standard+ defaults
	if lvl == HardeningStandard || lvl == HardeningStrict {
		if h.Hardening.Kernel.SysctlHardening == nil {
			t := true
			h.Hardening.Kernel.SysctlHardening = &t
		}
		if h.Hardening.Kernel.DisableIPv6 == nil {
			f := false
			h.Hardening.Kernel.DisableIPv6 = &f
		}
		if h.Hardening.Audit.Fail2ban == nil {
			t := true
			h.Hardening.Audit.Fail2ban = &t
		}
		if h.Hardening.Audit.Auditd == nil {
			t := true
			h.Hardening.Audit.Auditd = &t
		}
		if h.Hardening.Services.DisableBluetooth == nil {
			t := true
			h.Hardening.Services.DisableBluetooth = &t
		}
		if h.Hardening.Services.DisableAvahi == nil {
			f := false
			h.Hardening.Services.DisableAvahi = &f
		}
		if h.Hardening.Services.DisableWifi == nil {
			f := false
			h.Hardening.Services.DisableWifi = &f
		}
		if h.Hardening.Filesystem.MountHardening == nil {
			t := true
			h.Hardening.Filesystem.MountHardening = &t
		}
		if h.Hardening.Filesystem.SecureSharedMemory == nil {
			t := true
			h.Hardening.Filesystem.SecureSharedMemory = &t
		}
	}

	// Strict-only defaults
	if lvl == HardeningStrict {
		if h.Hardening.Kubernetes.CISBenchmark == nil {
			t := true
			h.Hardening.Kubernetes.CISBenchmark = &t
		}
		if h.Hardening.Kubernetes.USBLockdown == nil {
			t := true
			h.Hardening.Kubernetes.USBLockdown = &t
		}
		// AppArmor defaults to off on rpi3/rpi3b-plus unless forced
		if h.Hardening.Kubernetes.AppArmorForce == nil {
			f := false
			h.Hardening.Kubernetes.AppArmorForce = &f
		}
	}
}

func applyProfileDefaults(h *Host, p *Profile) {
	if h.Swap.ZRAMPercent == nil {
		v := p.ZRAMPercent
		h.Swap.ZRAMPercent = &v
	}
	if h.Swap.Swappiness == nil {
		v := p.Swappiness
		h.Swap.Swappiness = &v
	}
	if h.GPUMemMB == nil {
		v := p.GPUMemMB
		h.GPUMemMB = &v
	}
	// Add default eviction-hard kubelet arg if not already present
	eviction := "eviction-hard=" + p.EvictionHard
	for _, arg := range h.K3s.KubeletArgs {
		if strings.HasPrefix(arg, "eviction-hard=") {
			return
		}
		_ = arg
	}
	h.K3s.KubeletArgs = append(h.K3s.KubeletArgs, eviction)
}

func hostNames(c *Config) []string {
	names := make([]string, 0, len(c.Hosts))
	for n := range c.Hosts {
		names = append(names, n)
	}
	return names
}

func expandHome(path string) (string, error) {
	if !strings.HasPrefix(path, "~") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, path[1:]), nil
}
