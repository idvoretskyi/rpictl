// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT
package agent

import (
	"fmt"
	"os"
)

const (
	fail2banJailLocal = "/etc/fail2ban/jail.local"
)

const fail2banJailContent = `# Managed by rpictl — do not edit manually
[DEFAULT]
bantime  = 86400
findtime = 600
maxretry = 5
backend  = systemd

[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = %(sshd_log)s
maxretry = 5
`

// applyFail2ban applies Layer 4 — fail2ban SSH jail.
func applyFail2ban(input StepInput) ([]string, []string, error) {
	enabled := boolVal(boolPtr(input, "fail2ban"), false)
	if !enabled {
		return nil, nil, nil
	}

	hash := inputHash(fmt.Sprintf("%v", input["fail2ban"]))
	if hardeningMarkerExists("fail2ban", hash) {
		return nil, []string{"fail2ban: already applied"}, nil
	}

	if err := runApt("install", "-y", "-q", "fail2ban"); err != nil {
		return nil, nil, fmt.Errorf("install fail2ban: %w", err)
	}

	if err := backupFile(fail2banJailLocal); err != nil {
		return nil, nil, fmt.Errorf("backup fail2ban jail: %w", err)
	}

	safeJail, err := validateHardeningPath(fail2banJailLocal)
	if err != nil {
		return nil, nil, fmt.Errorf("validate fail2ban path: %w", err)
	}
	if err := os.MkdirAll("/etc/fail2ban", 0755); err != nil { // #nosec G301 -- /etc/fail2ban requires 0755 (standard system config dir)
		return nil, nil, fmt.Errorf("mkdir /etc/fail2ban: %w", err)
	}
	if err := os.WriteFile(safeJail, []byte(fail2banJailContent), 0644); err != nil { // #nosec G306 -- fail2ban jail.local must be world-readable (fail2ban reads as its own user)
		return nil, nil, fmt.Errorf("write fail2ban jail: %w", err)
	}

	if _, err := runCommand("systemctl", "enable", "--now", "fail2ban"); err != nil {
		return nil, nil, fmt.Errorf("enable fail2ban: %w", err)
	}
	if _, err := runCommand("systemctl", "reload", "fail2ban"); err != nil {
		// reload may fail if service just started — restart instead
		if _, err2 := runCommand("systemctl", "restart", "fail2ban"); err2 != nil {
			return nil, nil, fmt.Errorf("restart fail2ban: %w", err)
		}
	}

	writeHardeningMarker("fail2ban", hash)
	return []string{"fail2ban"}, []string{"fail2ban: sshd jail enabled (5 retries, 24h ban)"}, nil
}

// unhardenFail2ban removes fail2ban configuration.
func unhardenFail2ban() error {
	if err := restoreFile(fail2banJailLocal); err != nil {
		return fmt.Errorf("restore fail2ban jail: %w", err)
	}
	_ = os.Remove(fail2banJailLocal)
	_, _ = runCommand("systemctl", "reload", "fail2ban")
	removeHardeningMarker("fail2ban")
	return nil
}
