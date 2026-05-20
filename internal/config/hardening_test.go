// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHardeningLevelDefaults(t *testing.T) {
	cases := []struct {
		profile   string
		wantLevel HardeningLevel
	}{
		{"rpi3", HardeningBasic},
		{"rpi3b-plus", HardeningBasic},
		{"rpi4", HardeningStandard},
		{"rpi5", HardeningStandard},
	}
	for _, tc := range cases {
		h := &Host{DeviceProfile: tc.profile}
		applyHardeningDefaults(h)
		if h.Hardening.Level != tc.wantLevel {
			t.Errorf("profile=%q: level=%q, want %q", tc.profile, h.Hardening.Level, tc.wantLevel)
		}
	}
}

func TestHardeningPresetStandard(t *testing.T) {
	h := &Host{DeviceProfile: "rpi3b-plus"}
	h.Hardening.Level = HardeningStandard
	applyHardeningDefaults(h)

	assertBool := func(name string, got *bool, want bool) {
		t.Helper()
		if got == nil {
			t.Errorf("%s: nil, want %v", name, want)
			return
		}
		if *got != want {
			t.Errorf("%s: %v, want %v", name, *got, want)
		}
	}

	assertBool("sysctl_hardening", h.Hardening.Kernel.SysctlHardening, true)
	assertBool("fail2ban", h.Hardening.Audit.Fail2ban, true)
	assertBool("auditd", h.Hardening.Audit.Auditd, true)
	assertBool("disable_bluetooth", h.Hardening.Services.DisableBluetooth, true)
	assertBool("disable_avahi", h.Hardening.Services.DisableAvahi, false)
	assertBool("mount_hardening", h.Hardening.Filesystem.MountHardening, true)
	assertBool("rate_limit_ssh", h.Hardening.Firewall.RateLimitSSH, true)
	assertBool("allow_k3s_ports", h.Hardening.Firewall.AllowK3sPorts, true)
}

func TestHardeningPresetStrict(t *testing.T) {
	h := &Host{DeviceProfile: "rpi4"}
	h.Hardening.Level = HardeningStrict
	applyHardeningDefaults(h)

	if h.Hardening.Kubernetes.CISBenchmark == nil || !*h.Hardening.Kubernetes.CISBenchmark {
		t.Error("strict: cis_benchmark should be true")
	}
	if h.Hardening.Kubernetes.USBLockdown == nil || !*h.Hardening.Kubernetes.USBLockdown {
		t.Error("strict: usb_lockdown should be true")
	}
}

func TestHardeningAppArmorGateRpi3bPlus(t *testing.T) {
	h := &Host{DeviceProfile: "rpi3b-plus"}
	h.Hardening.Level = HardeningStrict
	applyHardeningDefaults(h)
	if h.Hardening.Kubernetes.AppArmorForce == nil || *h.Hardening.Kubernetes.AppArmorForce {
		t.Error("rpi3b-plus: apparmor_force should default to false (gate)")
	}
}

func TestHardeningUserOverrideWins(t *testing.T) {
	// User explicitly sets sysctl_hardening=false at standard level
	f := false
	h := &Host{DeviceProfile: "rpi4"}
	h.Hardening.Level = HardeningStandard
	h.Hardening.Kernel.SysctlHardening = &f
	applyHardeningDefaults(h)
	if h.Hardening.Kernel.SysctlHardening == nil || *h.Hardening.Kernel.SysctlHardening {
		t.Error("user override false should not be overwritten by preset")
	}
}

func TestHardeningValidationStrictRequiresPasswordAuthFalse(t *testing.T) {
	tr := true
	h := &Host{DeviceProfile: "rpi4"}
	h.Hardening.Level = HardeningStrict
	h.Hardening.SSH.PasswordAuth = &tr // this is invalid at strict level
	if err := validateHardening("rpi4-test", h); err == nil {
		t.Error("expected validation error for strict + password_auth=true")
	}
}

func TestLoadConfigHardeningDefaults(t *testing.T) {
	dir := t.TempDir()
	yaml := `hosts:
  rpi3:
    address: 192.168.1.1
    user: pi
    device_profile: rpi3b-plus
`
	cfgPath := filepath.Join(dir, "rpictl.yaml")
	if err := os.WriteFile(cfgPath, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	host := cfg.Hosts["rpi3"]
	if host.Hardening.Level != HardeningBasic {
		t.Errorf("expected basic for rpi3b-plus, got %q", host.Hardening.Level)
	}
	// SSH defaults
	if host.Hardening.SSH.PasswordAuth == nil || *host.Hardening.SSH.PasswordAuth {
		t.Error("expected password_auth=false by default")
	}
}

func TestLoadConfigMigrationShim(t *testing.T) {
	// Old-style config: hardening.ssh.password_auth set, no level field
	// Should parse without error and default to basic
	dir := t.TempDir()
	yaml := `hosts:
  rpi3:
    address: 192.168.1.1
    user: pi
    device_profile: rpi3b-plus
    hardening:
      ssh:
        password_auth: false
        permit_root_login: false
`
	cfgPath := filepath.Join(dir, "rpictl.yaml")
	if err := os.WriteFile(cfgPath, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load with old-style config: %v", err)
	}
	if cfg.Hosts["rpi3"].Hardening.Level != HardeningBasic {
		t.Errorf("old-style config should default to basic level")
	}
}
