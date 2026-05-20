// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT
package agent

import (
	"fmt"
	"os"
	"strings"
)

const (
	fstabPath            = "/etc/fstab"
	shmSystemdDropIn     = "/etc/systemd/system/dev-shm.mount.d/rpictl-hardening.conf"
	worldWritableStickyFixDone = "/var/lib/rpictl/hardening-mounts-sticky.done"
)

// applyMountHardening applies Layer 6 — mount hardening.
// Adds nodev,nosuid,noexec to /tmp, /var/tmp, /dev/shm.
// NEVER touches /var/lib/rancher (k3s). hidepid=2 on /proc.
func applyMountHardening(input StepInput) ([]string, []string, error) {
	mountHardening := boolVal(boolPtr(input, "mount_hardening"), false)
	secureShm := boolVal(boolPtr(input, "secure_shared_memory"), false)

	if !mountHardening && !secureShm {
		return nil, nil, nil
	}

	hash := inputHash(fmt.Sprintf("%v%v", input["mount_hardening"], input["secure_shared_memory"]))
	if hardeningMarkerExists("mounts", hash) {
		return nil, []string{"mounts: already applied"}, nil
	}

	var changed []string
	var msgs []string

	if mountHardening {
		c, m, err := applyFstabHardening()
		if err != nil {
			return nil, nil, err
		}
		changed = append(changed, c...)
		msgs = append(msgs, m...)
	}

	if secureShm {
		c, m, err := applySecureShm()
		if err != nil {
			return nil, nil, err
		}
		changed = append(changed, c...)
		msgs = append(msgs, m...)
	}

	// Fix sticky bit on world-writable directories
	if _, err := runCommand("find", "/", "-xdev", "-type", "d", "-perm", "-0002", "!", "-perm", "-1000",
		"-not", "-path", "/proc/*", "-not", "-path", "/sys/*", "-not", "-path", "/var/lib/rancher/*",
		"-exec", "chmod", "+t", "{}", ";"); err != nil {
		// Non-fatal: sticky bit fixup failure shouldn't abort provisioning
		msgs = append(msgs, fmt.Sprintf("sticky bit fixup: %v (non-fatal)", err))
	}

	writeHardeningMarker("mounts", hash)
	return changed, msgs, nil
}

// applyFstabHardening adds nodev,nosuid,noexec options to /tmp and /var/tmp.
func applyFstabHardening() ([]string, []string, error) {
	data, err := os.ReadFile(fstabPath) // #nosec G304 -- /etc/fstab is a known system path
	if err != nil {
		return nil, nil, fmt.Errorf("read fstab: %w", err)
	}

	if err := backupFile(fstabPath); err != nil {
		return nil, nil, fmt.Errorf("backup fstab: %w", err)
	}

	lines := splitLines(string(data))
	var modified []string
	changed := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			modified = append(modified, line)
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			modified = append(modified, line)
			continue
		}
		mountPoint := fields[1]
		// NEVER touch /var/lib/rancher (k3s) or /var/lib (could contain k3s data)
		if strings.HasPrefix(mountPoint, "/var/lib/rancher") {
			modified = append(modified, line)
			continue
		}
		if mountPoint == "/tmp" || mountPoint == "/var/tmp" {
			opts := fields[3]
			newOpts := addMountOptions(opts, []string{"nodev", "nosuid", "noexec"})
			if newOpts != opts {
				fields[3] = newOpts
				line = strings.Join(fields, "\t")
				changed = true
			}
		}
		modified = append(modified, line)
	}

	// If /tmp is not in fstab, add a tmpfs entry
	if !containsMount(lines, "/tmp") {
		modified = append(modified, "tmpfs\t/tmp\ttmpfs\tdefaults,nodev,nosuid,noexec\t0\t0")
		changed = true
	}
	if !containsMount(lines, "/var/tmp") {
		modified = append(modified, "tmpfs\t/var/tmp\ttmpfs\tdefaults,nodev,nosuid,noexec\t0\t0")
		changed = true
	}

	if changed {
		if err := writeAtomic(fstabPath, joinLines(modified)+"\n", 0644); err != nil {
			return nil, nil, fmt.Errorf("write fstab: %w", err)
		}
		// Remount /tmp and /var/tmp if they are already mounted
		for _, mp := range []string{"/tmp", "/var/tmp"} {
			_, _ = runCommand("mount", "-o", "remount", mp)
		}
	}

	return []string{"fstab-hardening"}, []string{"fstab: /tmp and /var/tmp hardened with nodev,nosuid,noexec"}, nil
}

// applySecureShm hardens /dev/shm via a systemd mount override.
func applySecureShm() ([]string, []string, error) {
	if err := os.MkdirAll("/etc/systemd/system/dev-shm.mount.d", 0755); err != nil { // #nosec G301 -- systemd drop-in dir, 0755 standard
		return nil, nil, fmt.Errorf("mkdir dev-shm drop-in: %w", err)
	}
	content := "[Mount]\nOptions=nodev,nosuid,noexec\n"
	if err := os.WriteFile(shmSystemdDropIn, []byte(content), 0644); err != nil { // #nosec G306 -- systemd conf, world-readable
		return nil, nil, fmt.Errorf("write dev-shm drop-in: %w", err)
	}
	_, _ = runCommand("systemctl", "daemon-reload")
	_, _ = runCommand("mount", "-o", "remount", "/dev/shm")
	return []string{"secure-shm"}, []string{"/dev/shm: nodev,nosuid,noexec applied via systemd"}, nil
}

// unhardenMounts restores fstab and removes shm drop-in.
func unhardenMounts() error {
	if err := restoreFile(fstabPath); err != nil {
		return fmt.Errorf("restore fstab: %w", err)
	}
	_ = os.Remove(shmSystemdDropIn)
	_, _ = runCommand("systemctl", "daemon-reload")
	removeHardeningMarker("mounts")
	return nil
}

// addMountOptions adds opts to the existing options string, deduplicating.
func addMountOptions(existing string, add []string) string {
	existing = strings.TrimSpace(existing)
	if existing == "" || existing == "defaults" {
		existing = "defaults"
	}
	current := strings.Split(existing, ",")
	have := make(map[string]bool, len(current))
	for _, o := range current {
		have[strings.TrimSpace(o)] = true
	}
	for _, o := range add {
		if !have[o] {
			current = append(current, o)
		}
	}
	return strings.Join(current, ",")
}

// containsMount returns true if any fstab line mounts the given path.
func containsMount(lines []string, mountPoint string) bool {
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == mountPoint {
			return true
		}
	}
	return false
}

func splitLines(s string) []string {
	return strings.Split(strings.TrimRight(s, "\n"), "\n")
}

func joinLines(lines []string) string {
	return strings.Join(lines, "\n")
}
