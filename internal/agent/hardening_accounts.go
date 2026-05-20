// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT
package agent

import (
	"fmt"
	"os"
	"strings"
)

const (
	pwqualityConf = "/etc/security/pwquality.conf"
	sudoersRpictl = "/etc/sudoers.d/rpictl-hardening" // #nosec G101 -- this is a file path, not a credential
	sudoersLog    = "/var/log/sudo.log"
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

	// Password quality policy
	if err := backupFile(pwqualityConf); err == nil {
		pwContent := `# Managed by rpictl — do not edit manually
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
`
		if err := os.WriteFile(pwqualityConf, []byte(pwContent), 0644); err == nil { // #nosec G306 -- pwquality.conf is world-readable
			changed = append(changed, "pwquality")
			msgs = append(msgs, "pwquality: minimum length 14, complexity enforced")
		}
	}

	// Sudo hardening: 5-minute session timeout + log to /var/log/sudo.log
	sudoersContent := `# Managed by rpictl — do not edit manually
Defaults timestamp_timeout=5
Defaults logfile=/var/log/sudo.log
Defaults log_input, log_output
`
	// Validate with visudo before writing
	if err := visudoValidate(sudoersContent); err == nil {
		if err := backupFile(sudoersRpictl); err == nil {
			if err := os.WriteFile(sudoersRpictl, []byte(sudoersContent), 0440); err == nil { // #nosec G306 -- sudoers.d requires 0440
				changed = append(changed, "sudoers-hardening")
				msgs = append(msgs, "sudoers: 5-min timeout, full logging enabled")
			}
		}
	}

	writeHardeningMarker("accounts", hash)
	return changed, msgs, nil
}

// unhardenAccounts reverses account hardening.
func unhardenAccounts() error {
	_ = restoreFile(pwqualityConf)
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

// appendLineIfMissing appends content to path if path does not already contain it.
func appendLineIfMissing(path, content string) error {
	existing := ""
	if data, err := os.ReadFile(path); err == nil { // #nosec G304 -- known config path
		existing = string(data)
	}
	if strings.Contains(existing, content) {
		return nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644) // #nosec G304 G306 -- config file, world-readable
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = f.WriteString(content)
	return err
}
