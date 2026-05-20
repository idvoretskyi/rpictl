// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT
package agent

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	sshdHardeningConf = "/etc/ssh/sshd_config.d/rpictl-hardening.conf"
	sshdBannerPath    = "/etc/issue.net"
)

const sshdBannerContent = `*******************************************************************
* Authorised access only. This system is privately owned.       *
* Disconnect IMMEDIATELY if you are not an authorised user.     *
* Unauthorised access and/or use is prohibited and may be       *
* subject to civil and/or criminal prosecution.                 *
*******************************************************************
`

// applySSHHardening applies Layer 1 — SSH hardening.
// Returns changed items. Caller MUST run sshdLivenessCheck after this.
func applySSHHardening(input StepInput) ([]string, []string, error) {
	passwordAuth := boolVal(boolPtr(input, "password_auth"), false)
	permitRoot := boolVal(boolPtr(input, "permit_root_login"), false)
	maxAuthTries := intVal(input, "max_auth_tries", 3)
	allowUsers, _ := input["allow_users"].([]interface{})
	banner := boolVal(boolPtr(input, "banner"), true)

	// Back up original before first write
	if err := backupFile(sshdHardeningConf); err != nil {
		return nil, nil, fmt.Errorf("backup sshd config: %w", err)
	}

	passwdVal := boolToYesNo(passwordAuth)
	rootVal := boolToYesNo(permitRoot)

	var sb strings.Builder
	sb.WriteString("# Managed by rpictl — do not edit manually\n")
	fmt.Fprintf(&sb, "PasswordAuthentication %s\n", passwdVal)
	fmt.Fprintf(&sb, "PermitRootLogin %s\n", rootVal)
	fmt.Fprintf(&sb, "KbdInteractiveAuthentication no\n")
	fmt.Fprintf(&sb, "MaxAuthTries %d\n", maxAuthTries)
	fmt.Fprintf(&sb, "LoginGraceTime 30\n")
	fmt.Fprintf(&sb, "ClientAliveInterval 300\n")
	fmt.Fprintf(&sb, "ClientAliveCountMax 2\n")
	fmt.Fprintf(&sb, "UseDNS no\n")
	// Modern ciphers / MACs / KexAlgorithms
	fmt.Fprintf(&sb, "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com\n")
	fmt.Fprintf(&sb, "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com\n")
	fmt.Fprintf(&sb, "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org\n")
	fmt.Fprintf(&sb, "HostKeyAlgorithms ssh-ed25519,sk-ssh-ed25519@openssh.com,rsa-sha2-512,rsa-sha2-256\n")

	if len(allowUsers) > 0 {
		users := make([]string, 0, len(allowUsers))
		for _, u := range allowUsers {
			if s, ok := u.(string); ok && s != "" {
				users = append(users, s)
			}
		}
		if len(users) > 0 {
			fmt.Fprintf(&sb, "AllowUsers %s\n", strings.Join(users, " "))
		}
	}

	if banner {
		// Write banner file
		if err := os.WriteFile(sshdBannerPath, []byte(sshdBannerContent), 0644); err != nil { // #nosec G306 -- banner is world-readable; SSH requires it
			return nil, nil, fmt.Errorf("write banner: %w", err)
		}
		fmt.Fprintf(&sb, "Banner %s\n", sshdBannerPath)
	}

	// Validate config before writing live
	newConf := sb.String()
	if err := sshdValidateNew(newConf); err != nil {
		return nil, nil, fmt.Errorf("sshd config validation failed: %w", err)
	}

	if err := writeAtomic(sshdHardeningConf, newConf, 0600); err != nil {
		return nil, nil, fmt.Errorf("write sshd config: %w", err)
	}

	// Reload sshd — try both service names used in different Debian versions
	if _, err := runCommand("systemctl", "reload", "ssh"); err != nil {
		if _, err2 := runCommand("systemctl", "reload", "sshd"); err2 != nil {
			// Restore backup on reload failure to avoid leaving a broken config
			_ = restoreFile(sshdHardeningConf)
			return nil, nil, fmt.Errorf("reload sshd: %w", err)
		}
	}

	changed := []string{"sshd-hardening"}
	msgs := []string{fmt.Sprintf("sshd: PasswordAuthentication=%s PermitRootLogin=%s MaxAuthTries=%d",
		passwdVal, rootVal, maxAuthTries)}
	return changed, msgs, nil
}

// unhardenSSH restores the pre-rpictl sshd config and reloads sshd.
func unhardenSSH() error {
	if err := restoreFile(sshdHardeningConf); err != nil {
		return fmt.Errorf("restore sshd config: %w", err)
	}
	// If no backup existed, remove our file entirely
	if _, err := os.Stat(sshdHardeningConf); err == nil {
		_ = os.Remove(sshdHardeningConf)
	}
	// Reload sshd
	if _, err := runCommand("systemctl", "reload", "ssh"); err != nil {
		_, _ = runCommand("systemctl", "reload", "sshd")
	}
	removeHardeningMarker("ssh")
	return nil
}

// sshdValidateNew writes the config to a temp file and validates it with sshd -t.
func sshdValidateNew(content string) error {
	tmp, err := os.CreateTemp("", "rpictl-sshd-*.conf")
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

	// sshd -t -f /dev/null -T reads Include directives from the main config;
	// we only validate our drop-in fragment by sourcing it via Match+Include trick.
	// The simplest reliable method is to write a full minimal sshd_config that
	// includes our fragment and run sshd -t -f <that file>.
	fullConf := "Port 22\n" + content
	fullTmp, err := os.CreateTemp("", "rpictl-sshd-full-*.conf")
	if err != nil {
		return err
	}
	defer func() {
		_ = fullTmp.Close()
		_ = os.Remove(fullTmp.Name())
	}()
	if _, err := fullTmp.WriteString(fullConf); err != nil {
		return err
	}
	_ = fullTmp.Close()

	out, err := exec.Command("sshd", "-t", "-f", fullTmp.Name()).CombinedOutput() // #nosec G204 -- sshd is a fixed binary, config path is a temp file we wrote
	if err != nil {
		return fmt.Errorf("sshd -t: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func boolToYesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// boolPtr extracts a *bool from StepInput by key.
func boolPtr(input StepInput, key string) *bool {
	v, ok := input[key].(bool)
	if !ok {
		return nil
	}
	return &v
}

// intVal extracts an int from StepInput by key, with a fallback default.
func intVal(input StepInput, key string, def int) int {
	switch v := input[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return def
}
