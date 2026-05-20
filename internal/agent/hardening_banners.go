// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT
package agent

import (
	"fmt"
	"os"
)

const (
	motdPath         = "/etc/motd"
	journaldConfPath = "/etc/systemd/journald.conf.d/rpictl-hardening.conf"
)

const bannerContent = `*******************************************************************
* Authorised access only. This system is privately owned.       *
* Disconnect IMMEDIATELY if you are not an authorised user.     *
*******************************************************************
`

const journaldContent = `# Managed by rpictl — do not edit manually
[Journal]
Storage=persistent
SystemMaxUse=200M
MaxRetentionSec=2week
`

// applyBannersAndJournald applies Layer 9 — login banners + journald persistence.
func applyBannersAndJournald(input StepInput) ([]string, []string, error) {
	enabled := boolVal(boolPtr(input, "banners"), false)
	if !enabled {
		return nil, nil, nil
	}

	hash := inputHash(fmt.Sprintf("%v", input["banners"]))
	if hardeningMarkerExists("banners", hash) {
		return nil, []string{"banners: already applied"}, nil
	}

	var changed []string
	var msgs []string

	// /etc/motd
	if err := backupFile(motdPath); err == nil {
		if err := os.WriteFile(motdPath, []byte(bannerContent), 0644); err == nil { // #nosec G306 -- motd is world-readable
			changed = append(changed, "motd")
			msgs = append(msgs, "motd: security banner written")
		}
	}

	// /etc/issue.net (referenced by sshd Banner directive in hardening_ssh.go)
	if err := backupFile(sshdBannerPath); err == nil {
		if err := os.WriteFile(sshdBannerPath, []byte(bannerContent), 0644); err == nil { // #nosec G306 -- issue.net is world-readable
			changed = append(changed, "issue.net")
			msgs = append(msgs, "issue.net: security banner written")
		}
	}

	// journald persistent logging
	if err := os.MkdirAll("/etc/systemd/journald.conf.d", 0755); err == nil { // #nosec G301 -- systemd conf dir, 0755 standard
		if err := os.WriteFile(journaldConfPath, []byte(journaldContent), 0644); err == nil { // #nosec G306 -- journald conf, world-readable
			changed = append(changed, "journald")
			msgs = append(msgs, "journald: persistent storage, 200MB max, 2-week retention")
			_, _ = runCommand("systemctl", "restart", "systemd-journald")
		}
	}

	writeHardeningMarker("banners", hash)
	return changed, msgs, nil
}

// unhardenBanners restores original banners and removes journald drop-in.
func unhardenBanners() error {
	_ = restoreFile(motdPath)
	_ = restoreFile(sshdBannerPath)
	_ = os.Remove(journaldConfPath)
	_, _ = runCommand("systemctl", "restart", "systemd-journald")
	removeHardeningMarker("banners")
	return nil
}

// applyNTP applies Layer 10 — NTP hardening via systemd-timesyncd.
func applyNTP(input StepInput) ([]string, []string, error) {
	enabled := boolVal(boolPtr(input, "ntp"), false)
	if !enabled {
		return nil, nil, nil
	}

	hash := inputHash(fmt.Sprintf("%v", input["ntp"]))
	if hardeningMarkerExists("ntp", hash) {
		return nil, []string{"ntp: already applied"}, nil
	}

	timesyncdConf := "/etc/systemd/timesyncd.conf"
	if err := backupFile(timesyncdConf); err != nil {
		return nil, nil, fmt.Errorf("backup timesyncd.conf: %w", err)
	}

	content := `# Managed by rpictl — do not edit manually
[Time]
NTP=1.1.1.1 1.0.0.1
FallbackNTP=0.pool.ntp.org 1.pool.ntp.org
`
	if err := os.WriteFile(timesyncdConf, []byte(content), 0644); err != nil { // #nosec G306 -- timesyncd.conf is world-readable
		return nil, nil, fmt.Errorf("write timesyncd.conf: %w", err)
	}

	if _, err := runCommand("systemctl", "enable", "--now", "systemd-timesyncd"); err != nil {
		return nil, nil, fmt.Errorf("enable timesyncd: %w", err)
	}
	if _, err := runCommand("systemctl", "restart", "systemd-timesyncd"); err != nil {
		return nil, nil, fmt.Errorf("restart timesyncd: %w", err)
	}

	writeHardeningMarker("ntp", hash)
	return []string{"ntp"}, []string{"NTP: Cloudflare NTP (1.1.1.1, 1.0.0.1) configured"}, nil
}

// unhardenNTP restores original timesyncd config.
func unhardenNTP() error {
	_ = restoreFile("/etc/systemd/timesyncd.conf")
	_, _ = runCommand("systemctl", "restart", "systemd-timesyncd")
	removeHardeningMarker("ntp")
	return nil
}
