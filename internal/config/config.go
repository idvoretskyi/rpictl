// Copyright 2026 Ihor Dvoretskyi
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-playground/validator/v10"
	"gopkg.in/yaml.v3"
)

// Config is the top-level rpictl.yaml structure.
type Config struct {
	Hosts map[string]*Host `yaml:"hosts" validate:"required,min=1"`
}

// Host represents a single target host in rpictl.yaml.
type Host struct {
	Address       string      `yaml:"address"        validate:"required"`
	User          string      `yaml:"user"           validate:"required"`
	SSHKey        string      `yaml:"ssh_key"`
	// KnownHostsFile is the path to the SSH known_hosts file used for host-key
	// verification. Defaults to ~/.ssh/known_hosts. Tilde is expanded.
	KnownHostsFile string `yaml:"known_hosts_file"`
	// StrictHostKey controls SSH host-key verification behaviour.
	// false (default): Trust On First Use — accept and persist an unknown host
	// key on the first connection; reject mismatches on subsequent connections.
	// true: reject any host not already present in known_hosts.
	StrictHostKey *bool       `yaml:"strict_host_key"`
	Timezone      string      `yaml:"timezone"`
	DeviceProfile string      `yaml:"device_profile"` // rpi3 | rpi3b-plus | rpi4 | rpi5 | auto
	Swap          SwapConfig  `yaml:"swap"`
	GPUMemMB      *int        `yaml:"gpu_mem"`
	K3s           K3sConfig   `yaml:"k3s"`
	Hardening     Hardening   `yaml:"hardening"`
	Kubeconfig    KubeconfigOut `yaml:"kubeconfig"`

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

// Hardening holds host hardening options.
type Hardening struct {
	SSH                SSHHardening `yaml:"ssh"`
	UFW                UFWConfig    `yaml:"ufw"`
	UnattendedUpgrades bool         `yaml:"unattended_upgrades"`
}

// SSHHardening holds SSH daemon config.
type SSHHardening struct {
	PasswordAuth    *bool `yaml:"password_auth"`
	PermitRootLogin *bool `yaml:"permit_root_login"`
}

// UFWConfig holds UFW firewall settings.
type UFWConfig struct {
	Enabled      bool     `yaml:"enabled"`
	AllowSSHFrom []string `yaml:"allow_ssh_from"`
}

// KubeconfigOut holds where to write the fetched kubeconfig.
type KubeconfigOut struct {
	Output  string `yaml:"output"`
	Context string `yaml:"context"`
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
		if err := applyDefaults(name, host); err != nil {
			return nil, fmt.Errorf("host %s: %w", name, err)
		}
	}

	return &cfg, nil
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

	// Default SSH hardening
	if h.Hardening.SSH.PasswordAuth == nil {
		f := false
		h.Hardening.SSH.PasswordAuth = &f
	}
	if h.Hardening.SSH.PermitRootLogin == nil {
		f := false
		h.Hardening.SSH.PermitRootLogin = &f
	}

	// Default kubeconfig output path
	if h.Kubeconfig.Output == "" {
		h.Kubeconfig.Output = fmt.Sprintf("~/.kube/%s.yaml", name)
	}
	if h.Kubeconfig.Context == "" {
		h.Kubeconfig.Context = name
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

	return nil
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
