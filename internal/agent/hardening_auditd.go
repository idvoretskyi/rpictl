// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT
package agent

import (
	"fmt"
	"os"
)

const (
	auditdRulesPath  = "/etc/audit/rules.d/rpictl-hardening.rules"
	auditdConfPath   = "/etc/audit/auditd.conf"
)

// auditdRules is a minimal audit rule set focused on authentication, privilege
// escalation, and critical config file changes. Deliberately lightweight for
// Pi 3B+ (1 GB RAM) — avoids filesystem-wide syscall watches.
const auditdRules = `# Managed by rpictl — do not edit manually
# Layer 5 — auditd minimal ruleset

# Buffer size — conservative for Pi 3B+ 1 GB RAM
-b 256

# Ignore errors (e.g. unavailable audit syscalls)
-i

# Login / session tracking
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# Privilege escalation
-w /etc/sudoers -p wa -k privilege_escalation
-w /etc/sudoers.d/ -p wa -k privilege_escalation

# Account changes
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity

# SSH config changes
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config

# Make config immutable (requires reboot to change rules)
# -e 2  # commented out — too aggressive for homelab use
`

// applyAuditd applies Layer 5 — auditd.
func applyAuditd(input StepInput) ([]string, []string, error) {
	enabled := boolVal(boolPtr(input, "auditd"), false)
	if !enabled {
		return nil, nil, nil
	}

	hash := inputHash(fmt.Sprintf("%v", input["auditd"]))
	if hardeningMarkerExists("auditd", hash) {
		return nil, []string{"auditd: already applied"}, nil
	}

	if err := runApt("install", "-y", "-q", "auditd", "audispd-plugins"); err != nil {
		return nil, nil, fmt.Errorf("install auditd: %w", err)
	}

	if err := os.MkdirAll("/etc/audit/rules.d", 0750); err != nil {
		return nil, nil, fmt.Errorf("mkdir audit rules: %w", err)
	}
	if err := backupFile(auditdRulesPath); err != nil {
		return nil, nil, fmt.Errorf("backup audit rules: %w", err)
	}
	safeRules, err := validateHardeningPath(auditdRulesPath)
	if err != nil {
		return nil, nil, fmt.Errorf("validate audit rules path: %w", err)
	}
	if err := os.WriteFile(safeRules, []byte(auditdRules), 0640); err != nil { // #nosec G306 G703 -- audit rules: 0640 (root:root) is standard; path validated by allowlist
		return nil, nil, fmt.Errorf("write audit rules: %w", err)
	}

	// Configure log rotation: max 50 MB, 7 rotations
	if err := configureAuditdConf(); err != nil {
		// non-fatal — default auditd.conf is acceptable
		_ = err
	}

	if _, err := runCommand("systemctl", "enable", "--now", "auditd"); err != nil {
		return nil, nil, fmt.Errorf("enable auditd: %w", err)
	}
	// Load new rules
	if _, err := runCommand("augenrules", "--load"); err != nil {
		// augenrules may not be available on all versions
		_, _ = runCommand("auditctl", "-R", auditdRulesPath)
	}

	writeHardeningMarker("auditd", hash)
	return []string{"auditd"}, []string{"auditd: enabled with minimal ruleset"}, nil
}

// configureAuditdConf adjusts log rotation limits in auditd.conf.
func configureAuditdConf() error {
	safe, err := validateHardeningPath(auditdConfPath)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(safe) // #nosec G304 -- path validated by validateHardeningPath allowlist
	if err != nil {
		return err
	}
	content := string(data)
	// Replace or append key settings
	content = replaceOrAppendConf(content, "max_log_file", "50")
	content = replaceOrAppendConf(content, "num_logs", "7")
	content = replaceOrAppendConf(content, "max_log_file_action", "ROTATE")
	return os.WriteFile(safe, []byte(content), 0640) // #nosec G306 G703 -- auditd.conf: 0640 is standard; path validated by allowlist
}

// replaceOrAppendConf updates "key = value" in content, or appends it.
func replaceOrAppendConf(content, key, value string) string {
	lines := splitLines(content)
	for i, line := range lines {
		if len(line) > len(key) && line[:len(key)] == key && (line[len(key)] == ' ' || line[len(key)] == '=') {
			lines[i] = fmt.Sprintf("%s = %s", key, value)
			return joinLines(lines)
		}
	}
	return content + fmt.Sprintf("\n%s = %s\n", key, value)
}

// unhardenAuditd removes audit rules and restores config.
func unhardenAuditd() error {
	if err := restoreFile(auditdRulesPath); err != nil {
		return fmt.Errorf("restore audit rules: %w", err)
	}
	_ = os.Remove(auditdRulesPath)
	_, _ = runCommand("augenrules", "--load")
	removeHardeningMarker("auditd")
	return nil
}
