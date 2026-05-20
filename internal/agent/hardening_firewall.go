// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT
package agent

import (
	"fmt"
	"strings"
)

// applyFirewallHardening applies Layer 2 — UFW firewall.
// SSH allow rule is added BEFORE changing default policy to deny,
// then rate-limiting is applied, and k3s ports are opened if requested.
// This ordering prevents self-lockout.
func applyFirewallHardening(input StepInput) ([]string, []string, error) {
	enabled := boolVal(boolPtr(input, "ufw_enabled"), false)
	if !enabled {
		return nil, nil, nil
	}

	// Install ufw if missing
	if _, err := runCommand("which", "ufw"); err != nil {
		if err2 := runApt("install", "-y", "-q", "ufw"); err2 != nil {
			return nil, nil, fmt.Errorf("install ufw: %w", err2)
		}
	}

	allowFrom, _ := input["allow_ssh_from"].([]interface{})
	rateLimitSSH := boolVal(boolPtr(input, "rate_limit_ssh"), false)
	allowK3sPorts := boolVal(boolPtr(input, "allow_k3s_ports"), false)

	// Step 1: allow SSH BEFORE setting default deny — critical to avoid lockout
	if len(allowFrom) == 0 {
		if _, err := runCommand("ufw", "allow", "ssh"); err != nil {
			return nil, nil, fmt.Errorf("ufw allow ssh: %w", err)
		}
	} else {
		for _, cidr := range allowFrom {
			cidrStr, _ := cidr.(string)
			if cidrStr == "" {
				continue
			}
			if _, err := runCommand("ufw", "allow", "from", cidrStr, "to", "any", "port", "22"); err != nil {
				return nil, nil, fmt.Errorf("ufw allow from %s: %w", cidrStr, err)
			}
		}
	}

	// Step 2: k3s ports (6443/tcp apiserver, 10250/tcp kubelet, 8472/udp flannel VXLAN)
	if allowK3sPorts {
		k3sPorts := [][]string{
			{"6443", "tcp"},
			{"10250", "tcp"},
			{"8472", "udp"},
		}
		for _, p := range k3sPorts {
			if _, err := runCommand("ufw", "allow", p[0]+"/"+p[1]); err != nil {
				return nil, nil, fmt.Errorf("ufw allow %s/%s: %w", p[0], p[1], err)
			}
		}
	}

	// Step 3: set default deny
	if _, err := runCommand("ufw", "default", "deny", "incoming"); err != nil {
		return nil, nil, fmt.Errorf("ufw default deny: %w", err)
	}
	if _, err := runCommand("ufw", "default", "allow", "outgoing"); err != nil {
		return nil, nil, fmt.Errorf("ufw default allow outgoing: %w", err)
	}

	// Step 4: rate-limit SSH (AFTER deny default is set, using ufw limit)
	if rateLimitSSH {
		if _, err := runCommand("ufw", "limit", "ssh"); err != nil {
			return nil, nil, fmt.Errorf("ufw limit ssh: %w", err)
		}
	}

	// Step 5: enable UFW
	if err := runCommandStdin("y\n", "ufw", "enable"); err != nil {
		return nil, nil, fmt.Errorf("ufw enable: %w", err)
	}

	var parts []string
	parts = append(parts, "UFW enabled")
	if rateLimitSSH {
		parts = append(parts, "SSH rate-limited")
	}
	if allowK3sPorts {
		parts = append(parts, "k3s ports open")
	}

	return []string{"ufw"}, []string{strings.Join(parts, "; ")}, nil
}

// unhardenFirewall resets UFW to disabled state.
func unhardenFirewall() error {
	// Disable UFW first (this allows all traffic temporarily, safe for recovery)
	if _, err := runCommand("ufw", "disable"); err != nil {
		return fmt.Errorf("ufw disable: %w", err)
	}
	if err := runCommandStdin("y\n", "ufw", "reset"); err != nil {
		return fmt.Errorf("ufw reset: %w", err)
	}
	removeHardeningMarker("firewall")
	return nil
}
