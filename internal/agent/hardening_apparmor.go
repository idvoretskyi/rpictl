// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT
package agent

import (
	"fmt"
	"os"
)

const (
	appArmorCmdlinePath = "/boot/firmware/cmdline.txt"
	usbLockdownPath     = "/etc/modprobe.d/rpictl-lockdown.conf"
)

// applyAppArmorAndUSB applies Layer 12 — AppArmor enforcement + USB storage lockdown.
// AppArmor is gated: on rpi3/rpi3b-plus it requires apparmor_force=true in config
// (RPi 3B+ 1 GB RAM — AppArmor is untested; default is off).
func applyAppArmorAndUSB(input StepInput) ([]string, []string, error) {
	appArmorForce := boolVal(boolPtr(input, "apparmor_force"), false)
	usbLockdown := boolVal(boolPtr(input, "usb_lockdown"), false)
	deviceProfile, _ := input["device_profile"].(string)

	if !appArmorForce && !usbLockdown {
		return nil, nil, nil
	}

	hash := inputHash(fmt.Sprintf("%v%v%v", appArmorForce, usbLockdown, deviceProfile))
	if hardeningMarkerExists("apparmor-usb", hash) {
		return nil, []string{"apparmor-usb: already applied"}, nil
	}

	var changed []string
	var msgs []string

	// AppArmor — gated on rpi3/rpi3b-plus
	if appArmorForce {
		isLowMem := deviceProfile == "rpi3" || deviceProfile == "rpi3b-plus"
		if isLowMem {
			msgs = append(msgs, "AppArmor: applying on rpi3/rpi3b-plus (apparmor_force=true; untested on this hardware)")
		}
		if err := enableAppArmor(); err != nil {
			return nil, nil, fmt.Errorf("enable AppArmor: %w", err)
		}
		changed = append(changed, "apparmor")
		msgs = append(msgs, "AppArmor: enabled; reboot required to fully activate")
	}

	// USB storage lockdown
	if usbLockdown {
		lockdownContent := "# Managed by rpictl — USB storage lockdown\nblacklist usb-storage\n"
		if err := os.WriteFile(usbLockdownPath, []byte(lockdownContent), 0644); err != nil { // #nosec G306 -- modprobe conf, world-readable
			return nil, nil, fmt.Errorf("write USB lockdown: %w", err)
		}
		// Update initramfs to apply the blacklist at boot
		_, _ = runCommand("update-initramfs", "-u")
		changed = append(changed, "usb-lockdown")
		msgs = append(msgs, "USB storage: usb-storage module blacklisted")
	}

	writeHardeningMarker("apparmor-usb", hash)
	return changed, msgs, nil
}

// enableAppArmor appends AppArmor boot parameters to cmdline.txt and
// sets containerd/runc profiles to enforce.
func enableAppArmor() error {
	data, err := os.ReadFile(appArmorCmdlinePath) // #nosec G304 -- /boot/firmware/cmdline.txt
	if err != nil {
		return fmt.Errorf("read cmdline.txt: %w", err)
	}
	if err := backupFile(appArmorCmdlinePath); err != nil {
		return fmt.Errorf("backup cmdline.txt: %w", err)
	}

	cmdline := string(data)
	if !containsWord(cmdline, "apparmor=1") {
		cmdline = trimNewline(cmdline) + " apparmor=1 security=apparmor\n"
	}
	if err := os.WriteFile(appArmorCmdlinePath, []byte(cmdline), 0755); err != nil { // #nosec G304 G306 -- /boot/firmware/cmdline.txt, executable bit required by bootloader
		return fmt.Errorf("write cmdline.txt: %w", err)
	}

	// Install apparmor-utils if not present
	if _, err := runCommand("which", "aa-status"); err != nil {
		if err := runApt("install", "-y", "-q", "apparmor", "apparmor-utils"); err != nil {
			return fmt.Errorf("install apparmor: %w", err)
		}
	}

	return nil
}

// unhardenAppArmorUSB reverses AppArmor and USB lockdown.
func unhardenAppArmorUSB() error {
	_ = restoreFile(appArmorCmdlinePath)
	_ = restoreFile(usbLockdownPath)
	_ = os.Remove(usbLockdownPath)
	_, _ = runCommand("update-initramfs", "-u")
	removeHardeningMarker("apparmor-usb")
	return nil
}

// containsWord reports whether word appears as a separate token in s.
func containsWord(s, word string) bool {
	for _, f := range splitFields(s) {
		if f == word {
			return true
		}
	}
	return false
}

// splitFields splits on spaces/tabs, trimming empty tokens.
func splitFields(s string) []string {
	var out []string
	for _, f := range splitBySpace(s) {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func splitBySpace(s string) []string {
	result := []string{}
	start := -1
	for i, c := range s {
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			if start >= 0 {
				result = append(result, s[start:i])
				start = -1
			}
		} else if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		result = append(result, s[start:])
	}
	return result
}

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
