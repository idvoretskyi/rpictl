// Copyright 2026 Ihor Dvoretskyi
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package agent

import (
	"fmt"
	"os"
	"strings"
)

const sshdConfig = `/etc/ssh/sshd_config.d/rpictl-hardening.conf`

// RunHardening applies SSH daemon hardening, UFW firewall, and unattended-upgrades.
func RunHardening(input StepInput) (*Result, error) {
	result := &Result{OK: true}

	// SSH hardening
	passwordAuth, _ := input["password_auth"].(bool)
	permitRoot, _ := input["permit_root_login"].(bool)

	passwdVal := "no"
	if passwordAuth {
		passwdVal = "yes"
	}
	rootVal := "no"
	if permitRoot {
		rootVal = "yes"
	}

	sshdContent := fmt.Sprintf("PasswordAuthentication %s\nPermitRootLogin %s\n", passwdVal, rootVal)
	if err := os.WriteFile(sshdConfig, []byte(sshdContent), 0644); err != nil {
		return nil, fmt.Errorf("write sshd config: %w", err)
	}
	if _, err := runCommand("systemctl", "reload", "ssh"); err != nil {
		// try sshd service name
		if _, err2 := runCommand("systemctl", "reload", "sshd"); err2 != nil {
			return nil, fmt.Errorf("reload sshd: %w", err)
		}
	}
	result.Changed = append(result.Changed, "sshd-hardening")
	result.Messages = append(result.Messages, fmt.Sprintf("sshd: PasswordAuthentication=%s PermitRootLogin=%s", passwdVal, rootVal))

	// UFW
	ufwEnabled, _ := input["ufw_enabled"].(bool)
	if ufwEnabled {
		// Install ufw if missing
		if _, err := runCommand("which", "ufw"); err != nil {
			if _, err2 := runCommand("apt-get", "install", "-y", "-q", "ufw"); err2 != nil {
				return nil, fmt.Errorf("install ufw: %w", err2)
			}
		}

		allowFrom, _ := input["allow_ssh_from"].([]interface{})
		if len(allowFrom) == 0 {
			// Allow SSH from anywhere as fallback — better than locking ourselves out
			if _, err := runCommand("ufw", "allow", "ssh"); err != nil {
				return nil, fmt.Errorf("ufw allow ssh: %w", err)
			}
		} else {
			for _, cidr := range allowFrom {
				cidrStr, _ := cidr.(string)
				if cidrStr == "" {
					continue
				}
				if _, err := runCommand("ufw", "allow", "from", cidrStr, "to", "any", "port", "22"); err != nil {
					return nil, fmt.Errorf("ufw allow from %s: %w", cidrStr, err)
				}
			}
		}
		if err := runCommandStdin("y\n", "ufw", "enable"); err != nil {
			return nil, fmt.Errorf("ufw enable: %w", err)
		}
		result.Changed = append(result.Changed, "ufw")
		result.Messages = append(result.Messages, "UFW enabled")
	}

	// Unattended upgrades
	unattended, _ := input["unattended_upgrades"].(bool)
	if unattended {
		if _, err := runCommand("apt-get", "install", "-y", "-q", "unattended-upgrades"); err != nil {
			return nil, fmt.Errorf("install unattended-upgrades: %w", err)
		}
		conf := `APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
`
		if err := os.WriteFile("/etc/apt/apt.conf.d/20auto-upgrades", []byte(conf), 0644); err != nil {
			return nil, fmt.Errorf("write auto-upgrades config: %w", err)
		}
		result.Changed = append(result.Changed, "unattended-upgrades")
		result.Messages = append(result.Messages, "unattended-upgrades enabled")
	}

	_ = strings.TrimSpace // suppress unused import
	return result, nil
}
