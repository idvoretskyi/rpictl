// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT
package agent

import (
	"fmt"
	"strings"
)

// applyServiceHardening applies Layer 7 — service trimming.
// Disables services that are unnecessary on a headless k3s Pi.
// avahi-daemon is kept by default (mDNS for raspberrypi.local).
func applyServiceHardening(input StepInput) ([]string, []string, error) {
	disableBT := boolVal(boolPtr(input, "disable_bluetooth"), false)
	disableAvahi := boolVal(boolPtr(input, "disable_avahi"), false)
	disableWifi := boolVal(boolPtr(input, "disable_wifi"), false)

	if !disableBT && !disableAvahi && !disableWifi {
		return nil, nil, nil
	}

	hash := inputHash(fmt.Sprintf("%v%v%v", disableBT, disableAvahi, disableWifi))
	if hardeningMarkerExists("services", hash) {
		return nil, []string{"services: already applied"}, nil
	}

	var disabled []string

	if disableBT {
		btServices := []string{"bluetooth.service", "hciuart.service"}
		for _, svc := range btServices {
			if serviceExists(svc) {
				if _, err := runCommand("systemctl", "disable", "--now", svc); err == nil {
					disabled = append(disabled, svc)
				}
			}
		}
		// Also blacklist btusb and bluetooth kernel modules
		_ = appendLineIfMissing("/etc/modprobe.d/rpictl-bluetooth.conf",
			"blacklist btusb\nblacklist bluetooth\n")
	}

	// Always disable clearly unnecessary services if present
	alwaysDisable := []string{"cups.service", "triggerhappy.service", "ModemManager.service"}
	for _, svc := range alwaysDisable {
		if serviceExists(svc) {
			if _, err := runCommand("systemctl", "disable", "--now", svc); err == nil {
				disabled = append(disabled, svc)
			}
		}
	}

	if disableAvahi {
		if serviceExists("avahi-daemon.service") {
			if _, err := runCommand("systemctl", "disable", "--now", "avahi-daemon.service"); err == nil {
				disabled = append(disabled, "avahi-daemon")
			}
		}
	}

	if disableWifi {
		if serviceExists("wpa_supplicant.service") {
			if _, err := runCommand("systemctl", "disable", "--now", "wpa_supplicant.service"); err == nil {
				disabled = append(disabled, "wpa_supplicant")
			}
		}
	}

	writeHardeningMarker("services", hash)
	if len(disabled) == 0 {
		return nil, []string{"services: no services required disabling"}, nil
	}
	return []string{"service-trimming"},
		[]string{fmt.Sprintf("services: disabled %s", strings.Join(disabled, ", "))},
		nil
}

// unhardenServices re-enables services that were disabled.
func unhardenServices() error {
	// We re-enable only known-safe ones; we don't track which were actually
	// disabled so we try all and ignore errors.
	toRestore := []string{
		"bluetooth.service", "hciuart.service",
		"avahi-daemon.service", "wpa_supplicant.service",
	}
	for _, svc := range toRestore {
		if serviceExists(svc) {
			_, _ = runCommand("systemctl", "enable", "--now", svc)
		}
	}
	removeHardeningMarker("services")
	return nil
}

// serviceExists returns true if a systemd unit file is known.
func serviceExists(name string) bool {
	out, err := runCommand("systemctl", "list-unit-files", name)
	if err != nil {
		return false
	}
	return strings.Contains(out, name)
}
