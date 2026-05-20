// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT
package agent

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// hardeningMarkerDir is where per-layer done markers are stored.
const hardeningMarkerDir = "/var/lib/rpictl"

// hardeningAllowedPaths is the exhaustive set of system file paths that the
// hardening agent is permitted to read, write, or back up. Any path not in
// this set will be rejected by validateHardeningPath. This acts as a
// defence-in-depth measure and resolves gosec G304 taint findings by
// making the sanitisation explicit and verifiable.
var hardeningAllowedPaths = map[string]struct{}{
	// Layer 1 — SSH
	"/etc/ssh/sshd_config.d/rpictl-hardening.conf": {},
	"/etc/issue.net": {},

	// Layer 2 — UFW (no files managed directly; ufw CLI only)

	// Layer 3 — sysctl
	"/etc/sysctl.d/99-rpictl-hardening.conf": {},

	// Layer 4 — fail2ban
	"/etc/fail2ban/jail.local": {},

	// Layer 5 — auditd
	"/etc/audit/rules.d/rpictl-hardening.rules": {},
	"/etc/audit/auditd.conf":                    {},

	// Layer 6 — mounts
	"/etc/fstab": {},
	"/etc/systemd/system/dev-shm.mount.d/rpictl-hardening.conf": {},

	// Layer 7 — services
	"/etc/modprobe.d/rpictl-bluetooth.conf": {},

	// Layer 8 — accounts
	"/etc/security/pwquality.conf":    {},
	"/etc/sudoers.d/rpictl-hardening": {},

	// Layer 9 — banners / journald
	"/etc/motd": {},
	"/etc/systemd/journald.conf.d/rpictl-hardening.conf": {},

	// Layer 10 — NTP
	"/etc/systemd/timesyncd.conf": {},

	// Layer 11 — k3s CIS
	"/etc/rancher/k3s/config.yaml": {},
	"/etc/rancher/k3s/audit.yaml":  {},
	"/etc/logrotate.d/k3s-audit":   {},

	// Layer 12 — AppArmor + USB lockdown
	"/boot/firmware/cmdline.txt":           {},
	"/etc/modprobe.d/rpictl-lockdown.conf": {},
}

// validateHardeningPath cleans path and confirms it is in the hardening
// allowlist. Returns the cleaned path on success, error otherwise.
// filepath.Clean is a recognised sanitiser for gosec's G304 taint analysis.
func validateHardeningPath(p string) (string, error) {
	clean := filepath.Clean(p)
	if _, ok := hardeningAllowedPaths[clean]; !ok {
		return "", fmt.Errorf("path %q is not in the hardening path allowlist", p)
	}
	return clean, nil
}

// allowHardeningPathForTest registers an additional path in the allowlist.
// It is intended exclusively for use in tests (same package) and must not be
// called from production code paths.
func allowHardeningPathForTest(p string) {
	hardeningAllowedPaths[filepath.Clean(p)] = struct{}{}
}

// hardeningLayerMarkerPath returns the marker path for a given hardening layer.
func hardeningLayerMarkerPath(layer string) string {
	return filepath.Join(hardeningMarkerDir, "hardening-"+layer+".done")
}

// hardeningMarkerContent produces a sortable timestamp-based marker content
// with an input hash so we can detect config changes.
func hardeningMarkerContent(inputHash string) string {
	return fmt.Sprintf("%s %s", time.Now().UTC().Format(time.RFC3339), inputHash)
}

// writeHardeningMarker writes a done-marker for a hardening layer.
func writeHardeningMarker(layer, inputHash string) {
	if err := os.MkdirAll(hardeningMarkerDir, 0750); err != nil {
		return
	}
	p := hardeningLayerMarkerPath(layer)
	_ = os.WriteFile(p, []byte(hardeningMarkerContent(inputHash)), 0600)
}

// hardeningMarkerExists returns true if a layer's done marker exists with a
// matching hash, indicating the layer was already applied with the same config.
func hardeningMarkerExists(layer, inputHash string) bool {
	p := hardeningLayerMarkerPath(layer)
	data, err := os.ReadFile(p) // #nosec G304 -- path constructed from fixed constant dir + hardcoded layer name
	if err != nil {
		return false
	}
	return strings.Contains(string(data), inputHash)
}

// removeHardeningMarker deletes the done-marker for a hardening layer.
// Used by unharden operations.
func removeHardeningMarker(layer string) {
	_ = os.Remove(hardeningLayerMarkerPath(layer))
}

// backupFile copies src to src+".bak.rpictl" preserving mode.
// It is idempotent: if the backup already exists, it is not overwritten (we
// only ever want to preserve the pre-rpictl state, not a previously-rpictl-written file).
// The path is validated against the hardening allowlist before any I/O.
func backupFile(path string) error {
	safe, err := validateHardeningPath(path)
	if err != nil {
		return err
	}

	bak := safe + ".bak.rpictl"
	if _, err := os.Stat(bak); err == nil {
		return nil // backup already exists — leave original backup intact
	}

	src, err := os.Open(safe) // #nosec G304 -- path validated by validateHardeningPath allowlist
	if err != nil {
		if os.IsNotExist(err) {
			return nil // file doesn't exist yet, nothing to back up
		}
		return fmt.Errorf("open %s: %w", safe, err)
	}
	defer func() { _ = src.Close() }()

	info, err := src.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", safe, err)
	}

	dst, err := os.OpenFile(bak, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm()) // #nosec G304 -- bak is safe+".bak.rpictl", safe validated by allowlist
	if err != nil {
		return fmt.Errorf("create backup %s: %w", bak, err)
	}
	defer func() { _ = dst.Close() }()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("copy to backup %s: %w", bak, err)
	}
	return nil
}

// restoreFile restores path from its ".bak.rpictl" backup and removes the backup.
// Returns nil (no error) if no backup exists.
// The path is validated against the hardening allowlist before any I/O.
func restoreFile(path string) error {
	safe, err := validateHardeningPath(path)
	if err != nil {
		return err
	}

	bak := safe + ".bak.rpictl"
	if _, err := os.Stat(bak); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(bak) // #nosec G304 -- bak is safe+".bak.rpictl", safe validated by allowlist
	if err != nil {
		return fmt.Errorf("read backup %s: %w", bak, err)
	}

	info, err := os.Stat(bak)
	if err != nil {
		return fmt.Errorf("stat backup %s: %w", bak, err)
	}

	if err := os.WriteFile(safe, data, info.Mode().Perm()); err != nil { // #nosec G703 -- path validated by validateHardeningPath allowlist
		return fmt.Errorf("restore %s: %w", safe, err)
	}
	_ = os.Remove(bak)
	return nil
}

// writeAtomic writes content to path atomically: writes to path+".new",
// then renames. Preserves the original file's mode if it exists, else uses mode.
// The path is validated against the hardening allowlist before any I/O.
func writeAtomic(path, content string, mode os.FileMode) error {
	safe, err := validateHardeningPath(path)
	if err != nil {
		return err
	}

	// Preserve existing mode if the file already exists.
	if info, err := os.Stat(safe); err == nil {
		mode = info.Mode().Perm()
	}

	tmp := safe + ".new"
	if err := os.WriteFile(tmp, []byte(content), mode); err != nil { // #nosec G703 G306 -- tmp is safe+".new", safe validated by allowlist; mode is system-mandated
		return fmt.Errorf("write tmp %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, safe); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s -> %s: %w", tmp, safe, err)
	}
	return nil
}

// boolVal safely dereferences a *bool, returning the fallback if nil.
func boolVal(b *bool, fallback bool) bool {
	if b == nil {
		return fallback
	}
	return *b
}
