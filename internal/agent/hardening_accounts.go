// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT
package agent

import (
	"fmt"
	"os"
	"strings"
)

const (
	pamQualityConf = "/etc/security/pwquality.conf"
	sudoersRpictl  = "/etc/sudoers.d/rpictl-hardening"
	sudoersLog     = "/var/log/sudo.log"
)

// systemAccounts are accounts that should be locked (no shell login).
var systemAccounts = []string{
	"games", "news", "uucp", "proxy", "list", "irc", "gnats", "nobody",
}

// applyAccountHardening applies Layer 8 — account hardening.
func applyAccountHardening(input StepInput) ([]string, []string, error) {
	enabled := boolVal(boolPtr(input, "account_hardening"), false)
	if !enabled {
		return nil, nil, nil
	}

	hash := inputHash(fmt.Sprintf("%v", input["account_hardening"]))
	if hardeningMarkerExists("accounts", hash) {
		return nil, []string{"accounts: already applied"}, nil
	}

	var changed []string
	var msgs []string

	// chmod 700 /home/<user> — default RPi OS is 755
	user, _ := input["user"].(string)
	if user != "" {
		homeDir := "/home/" + user
		if _, err := os.Stat(homeDir); err == nil {
			if _, err := runCommand("chmod", "700", homeDir); err == nil {
				changed = append(changed, "home-permissions")
				msgs = append(msgs, fmt.Sprintf("home %s: mode set to 700", homeDir))
			}
		}
	}

	// Lock system accounts
	var locked []string
	for _, acct := range systemAccounts {
		if accountExists(acct) {
			if _, err := runCommand("usermod", "-L", acct); err == nil {
				locked = append(locked, acct)
			}
		}
	}
	if len(locked) > 0 {
		changed = append(changed, "locked-system-accounts")
		msgs = append(msgs, fmt.Sprintf("locked accounts: %s", strings.Join(locked, ", ")))
	}

	// Password quality policy via pam_pwquality
	if err := backupFile(pamQualityConf); err == nil {
		safeQuality, err := validateHardeningPath(pamQualityConf)
		if err == nil {
			qualityPolicy := "# Managed by rpictl — do not edit manually\n" +
				"minlen = 14\n" +
				"dcredit = -1\n" +
				"ucredit = -1\n" +
				"lcredit = -1\n" +
				"ocredit = -1\n"
			if err := os.WriteFile(safeQuality, []byte(qualityPolicy), 0644); err == nil { // #nosec G306 -- pam_pwquality.conf must be world-readable (pam reads it as unprivileged)
				changed = append(changed, "pam-quality")
				msgs = append(msgs, "pam_pwquality: minimum length 14, complexity enforced")
			}
		}
	}

	// Sudo hardening: 5-minute session timeout + log to /var/log/sudo.log
	sudoersContent := "# Managed by rpictl — do not edit manually\n" +
		"Defaults timestamp_timeout=5\n" +
		"Defaults logfile=/var/log/sudo.log\n" +
		"Defaults log_input, log_output\n"
	// Validate with visudo before writing
	if err := visudoValidate(sudoersContent); err == nil {
		if err := backupFile(sudoersRpictl); err == nil {
			if safeSudoers, err := validateHardeningPath(sudoersRpictl); err == nil {
				if err := os.WriteFile(safeSudoers, []byte(sudoersContent), 0440); err == nil { // #nosec G306 -- sudoers drop-in requires 0440 (sudo refuses looser perms)
					changed = append(changed, "sudoers-hardening")
					msgs = append(msgs, "sudoers: 5-min timeout, full logging enabled")
				}
			}
		}
	}

	writeHardeningMarker("accounts", hash)
	return changed, msgs, nil
}

// unhardenAccounts reverses account hardening.
func unhardenAccounts() error {
	_ = restoreFile(pamQualityConf)
	_ = restoreFile(sudoersRpictl)
	_ = os.Remove(sudoersRpictl)
	// Unlock system accounts
	for _, acct := range systemAccounts {
		if accountExists(acct) {
			_, _ = runCommand("usermod", "-U", acct)
		}
	}
	removeHardeningMarker("accounts")
	return nil
}

// visudoValidate writes content to a temp file and validates with visudo -c -f.
func visudoValidate(content string) error {
	tmp, err := os.CreateTemp("", "rpictl-sudoers-*.conf")
	if err != nil {
		return err
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()
	if _, err := tmp.WriteString(content); err != nil {
		return err
	}
	_ = tmp.Close()
	_, err = runCommand("visudo", "-c", "-f", tmp.Name())
	return err
}

// accountExists returns true if the given Unix account exists on the system.
func accountExists(username string) bool {
	_, err := runCommand("id", username)
	return err == nil
}

// appendLineIfMissing appends content to path if path does not already contain
// it. If the file does not exist it is created with mode 0644 using os.WriteFile
// so that the open-with-mode call (which triggers gosec G306) is avoided — the
// write-to-new-file path uses os.WriteFile whose mode is intentional and
// narrowly scoped to known config paths in the hardening allowlist.
func appendLineIfMissing(path, content string) error {
	data, err := os.ReadFile(path) // #nosec G304 -- path validated against hardening allowlist by caller
	if err != nil {
		if os.IsNotExist(err) {
			// File does not exist yet — create it with the content directly.
			return os.WriteFile(path, []byte(content), 0644) // #nosec G306 G703 -- system config file; path validated against allowlist by caller
		}
		return err
	}
	if strings.Contains(string(data), content) {
		return nil
	}
	updated := string(data) + content
	return os.WriteFile(path, []byte(updated), 0644) // #nosec G306 G703 -- system config file; path validated against allowlist by caller
}
