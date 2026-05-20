// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT
package agent

import (
	"fmt"
)

// RunHardening is the main hardening dispatcher. It applies layers in
// dependency order based on the requested level:
//
//   off      — no-op (returns immediately)
//   basic    — Layer 1 (SSH) + Layer 2 (UFW) + unattended-upgrades
//   standard — basic + Layers 3–10
//   strict   — standard + Layers 11–12
//
// Each layer is individually idempotent via /var/lib/rpictl/hardening-<layer>.done
// markers. Layers 1 (SSH) and 2 (UFW) are applied last among system layers
// because they are the only ones that can cause network lockout.
// The caller (orchestrator) is responsible for performing an SSH liveness
// check after RunHardening returns and triggering rollback if needed.
func RunHardening(input StepInput) (*Result, error) {
	level, _ := input["level"].(string)
	if level == "off" {
		return &Result{OK: true, Skipped: true, Messages: []string{"hardening: level=off, skipping all layers"}}, nil
	}

	result := &Result{OK: true}

	// unattended-upgrades (all levels except off)
	if c, m, err := applyUnattendedUpgrades(input); err != nil {
		return result, fmt.Errorf("unattended-upgrades: %w", err)
	} else {
		result.Changed = append(result.Changed, c...)
		result.Messages = append(result.Messages, m...)
	}

	// standard+ layers applied before SSH/UFW (no lockout risk)
	if level == "standard" || level == "strict" {
		layers := []struct {
			name string
			fn   func(StepInput) ([]string, []string, error)
		}{
			{"sysctl", applySysctlHardening},
			{"services", applyServiceHardening},
			{"banners", applyBannersAndJournald},
			{"ntp", applyNTP},
			{"fail2ban", applyFail2ban},
			{"auditd", applyAuditd},
			{"accounts", applyAccountHardening},
			{"mounts", applyMountHardening},
		}
		for _, l := range layers {
			c, m, err := l.fn(input)
			if err != nil {
				return result, fmt.Errorf("layer %s: %w", l.name, err)
			}
			result.Changed = append(result.Changed, c...)
			result.Messages = append(result.Messages, m...)
		}
	}

	// strict-only layers (applied before SSH/UFW so we don't race with lockout)
	if level == "strict" {
		if c, m, err := applyK3sCIS(input); err != nil {
			return result, fmt.Errorf("layer k3s-cis: %w", err)
		} else {
			result.Changed = append(result.Changed, c...)
			result.Messages = append(result.Messages, m...)
		}
		if c, m, err := applyAppArmorAndUSB(input); err != nil {
			return result, fmt.Errorf("layer apparmor-usb: %w", err)
		} else {
			result.Changed = append(result.Changed, c...)
			result.Messages = append(result.Messages, m...)
		}
	}

	// Layer 2 — UFW (applied before SSH to ensure SSH allow rule is in place)
	if level != "off" {
		if c, m, err := applyFirewallHardening(input); err != nil {
			return result, fmt.Errorf("layer firewall: %w", err)
		} else {
			result.Changed = append(result.Changed, c...)
			result.Messages = append(result.Messages, m...)
		}
	}

	// Layer 1 — SSH hardening (applied last — highest lockout risk).
	// The orchestrator MUST run an SSH liveness check after this returns.
	if c, m, err := applySSHHardening(input); err != nil {
		return result, fmt.Errorf("layer ssh: %w", err)
	} else {
		result.Changed = append(result.Changed, c...)
		result.Messages = append(result.Messages, m...)
	}

	return result, nil
}

// applyUnattendedUpgrades installs and enables unattended-upgrades.
func applyUnattendedUpgrades(input StepInput) ([]string, []string, error) {
	enabled := boolVal(boolPtr(input, "unattended_upgrades"), false)
	if !enabled {
		return nil, nil, nil
	}

	if err := runApt("install", "-y", "-q", "unattended-upgrades"); err != nil {
		return nil, nil, fmt.Errorf("install unattended-upgrades: %w", err)
	}

	conf := `APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
`
	if err := writeAtomic("/etc/apt/apt.conf.d/20auto-upgrades", conf, 0644); err != nil { // #nosec G306 -- apt convention requires world-readable conf.d files
		return nil, nil, fmt.Errorf("write auto-upgrades config: %w", err)
	}
	return []string{"unattended-upgrades"}, []string{"unattended-upgrades: enabled"}, nil
}

// RunUnhardenSSH rolls back SSH hardening. Called by the orchestrator when
// the SSH liveness check fails after RunHardening.
func RunUnhardenSSH() error {
	return unhardenSSH()
}

// RunUnharden reverses all hardening layers that have done-markers.
// Called by the unharden agent operation.
func RunUnharden(input StepInput) (*Result, error) {
	result := &Result{OK: true}

	layers := []struct {
		name string
		fn   func() error
	}{
		{"k3s-cis", unhardenK3sCIS},
		{"apparmor-usb", unhardenAppArmorUSB},
		{"mounts", unhardenMounts},
		{"accounts", unhardenAccounts},
		{"auditd", unhardenAuditd},
		{"fail2ban", unhardenFail2ban},
		{"banners", unhardenBanners},
		{"ntp", unhardenNTP},
		{"services", unhardenServices},
		{"sysctl", unhardenSysctl},
		{"firewall", unhardenFirewall},
		{"ssh", unhardenSSH},
	}

	specificLayers, _ := input["layers"].([]interface{})
	layerFilter := map[string]bool{}
	for _, l := range specificLayers {
		if s, ok := l.(string); ok {
			layerFilter[s] = true
		}
	}

	for _, l := range layers {
		// Skip if a layer filter was specified and this layer isn't in it
		if len(layerFilter) > 0 && !layerFilter[l.name] {
			continue
		}
		// Only run if marker exists
		if _, err := markerExists(l.name); !err {
			continue
		}
		if err := l.fn(); err != nil {
			result.Messages = append(result.Messages, fmt.Sprintf("unharden %s: %v", l.name, err))
			// Continue: try to undo as many layers as possible
		} else {
			result.Changed = append(result.Changed, l.name)
			result.Messages = append(result.Messages, fmt.Sprintf("unharden %s: done", l.name))
		}
	}

	return result, nil
}

// markerExists returns true (as second bool) if the hardening marker for layer exists.
func markerExists(layer string) (string, bool) {
	path := hardeningLayerMarkerPath(layer)
	if _, err := readFile(path); err != nil {
		return path, false
	}
	return path, true
}
