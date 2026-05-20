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

	// /etc/motd — world-readable login message of the day
	if safeMotd, err := validateHardeningPath(motdPath); err == nil {
		if err := backupFile(motdPath); err == nil {
			if err := os.WriteFile(safeMotd, []byte(bannerContent), 0644); err == nil { // #nosec G306 -- /etc/motd must be world-readable
				changed = append(changed, "motd")
				msgs = append(msgs, "motd: security banner written")
			}
		}
	}

	// /etc/issue.net — world-readable; referenced by sshd Banner directive
	if safeIssue, err := validateHardeningPath(sshdBannerPath); err == nil {
		if err := backupFile(sshdBannerPath); err == nil {
			if err := os.WriteFile(safeIssue, []byte(bannerContent), 0644); err == nil { // #nosec G306 -- /etc/issue.net must be world-readable (sshd reads it pre-auth)
				changed = append(changed, "issue.net")
				msgs = append(msgs, "issue.net: security banner written")
			}
		}
	}

	// journald persistent logging — drop-in config, world-readable
	if safeJournald, err := validateHardeningPath(journaldConfPath); err == nil {
		if err := os.MkdirAll("/etc/systemd/journald.conf.d", 0755); err == nil { // #nosec G301 -- systemd drop-in dirs require 0755
			if err := os.WriteFile(safeJournald, []byte(journaldContent), 0644); err == nil { // #nosec G306 -- journald drop-in must be world-readable
				changed = append(changed, "journald")
				msgs = append(msgs, "journald: persistent storage, 200MB max, 2-week retention")
				_, _ = runCommand("systemctl", "restart", "systemd-journald")
			}
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

	const timesyncdConf = "/etc/systemd/timesyncd.conf"
	safeConf, err := validateHardeningPath(timesyncdConf)
	if err != nil {
		return nil, nil, fmt.Errorf("validate timesyncd path: %w", err)
	}

	if err := backupFile(timesyncdConf); err != nil {
		return nil, nil, fmt.Errorf("backup timesyncd.conf: %w", err)
	}

	content := "# Managed by rpictl — do not edit manually\n" +
		"[Time]\n" +
		"NTP=1.1.1.1 1.0.0.1\n" +
		"FallbackNTP=0.pool.ntp.org 1.pool.ntp.org\n"
	if err := os.WriteFile(safeConf, []byte(content), 0644); err != nil { // #nosec G306 -- timesyncd.conf must be world-readable (systemd reads as own user)
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
