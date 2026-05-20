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
	_ = os.WriteFile(hardeningLayerMarkerPath(layer), []byte(hardeningMarkerContent(inputHash)), 0600) // #nosec G306 -- marker is a hash, no sensitive data
}

// hardeningMarkerExists returns true if a layer's done marker exists with a
// matching hash, indicating the layer was already applied with the same config.
func hardeningMarkerExists(layer, inputHash string) bool {
	data, err := os.ReadFile(hardeningLayerMarkerPath(layer)) // #nosec G304 -- path constructed from trusted constant + layer name
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

// backupFile copies src to src+".bak.rpictl" preserving mode, owner, and group.
// It is idempotent: if the backup already exists, it is not overwritten (we
// only ever want to preserve the pre-rpictl state, not a previously-rpictl-written file).
func backupFile(path string) error {
	bak := path + ".bak.rpictl"
	if _, err := os.Stat(bak); err == nil {
		return nil // backup already exists — leave original backup intact
	}
	src, err := os.Open(path) // #nosec G304 -- path is a hardcoded system config path
	if err != nil {
		if os.IsNotExist(err) {
			return nil // file doesn't exist yet, nothing to back up
		}
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = src.Close() }()

	info, err := src.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	dst, err := os.OpenFile(bak, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm()) // #nosec G304 -- bak path constructed from system config path
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
func restoreFile(path string) error {
	bak := path + ".bak.rpictl"
	if _, err := os.Stat(bak); os.IsNotExist(err) {
		return nil
	}
	// Read backup
	data, err := os.ReadFile(bak) // #nosec G304 -- path constructed from trusted system config path
	if err != nil {
		return fmt.Errorf("read backup %s: %w", bak, err)
	}
	// Get mode from backup file
	info, err := os.Stat(bak)
	if err != nil {
		return fmt.Errorf("stat backup %s: %w", bak, err)
	}
	if err := os.WriteFile(path, data, info.Mode().Perm()); err != nil { // #nosec G304 G306 -- writing system config file back
		return fmt.Errorf("restore %s: %w", path, err)
	}
	_ = os.Remove(bak)
	return nil
}

// writeAtomic writes content to path atomically: writes to path+".new",
// then renames. Preserves the original file's mode if it exists, else uses mode.
// #nosec G306 -- mode is from existing file or explicitly provided by caller
func writeAtomic(path, content string, mode os.FileMode) error {
	// Preserve existing mode
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}

	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(content), mode); err != nil { // #nosec G304 G306 -- tmp path constructed from system config path
		return fmt.Errorf("write tmp %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s -> %s: %w", tmp, path, err)
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


