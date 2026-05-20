// Copyright 2026 Ihor Dvoretskyi
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEnsureCgroupMemoryAddsParams verifies that the cgroup kernel parameters
// are appended to cmdline.txt when absent. Without this fix, k3s v1.36 fails
// to start on Raspberry Pi OS with "failed to find memory cgroup (v2)".
func TestEnsureCgroupMemoryAddsParams(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cmdline.txt")

	initial := "console=serial0,115200 console=tty1 root=PARTUUID=abc rootfstype=ext4 rootwait\n"
	if err := os.WriteFile(path, []byte(initial), 0644); err != nil { // #nosec G306 -- test file in t.TempDir()
		t.Fatalf("write cmdline: %v", err)
	}

	changed, err := ensureCgroupMemoryAt(path)
	if err != nil {
		t.Fatalf("ensureCgroupMemoryAt: %v", err)
	}
	if !changed {
		t.Error("expected changed=true when params are absent")
	}

	data, _ := os.ReadFile(path) // #nosec G304 -- test file path from t.TempDir()
	content := string(data)
	if !strings.Contains(content, "cgroup_memory=1") {
		t.Errorf("cgroup_memory=1 not found in cmdline.txt:\n%s", content)
	}
	if !strings.Contains(content, "cgroup_enable=memory") {
		t.Errorf("cgroup_enable=memory not found in cmdline.txt:\n%s", content)
	}
}

func TestEnsureCgroupMemoryIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cmdline.txt")

	initial := "console=tty1 root=PARTUUID=abc cgroup_memory=1 cgroup_enable=memory rootwait\n"
	if err := os.WriteFile(path, []byte(initial), 0644); err != nil { // #nosec G306 -- test file in t.TempDir()
		t.Fatalf("write cmdline: %v", err)
	}

	changed, err := ensureCgroupMemoryAt(path)
	if err != nil {
		t.Fatalf("ensureCgroupMemoryAt: %v", err)
	}
	if changed {
		t.Error("expected changed=false when params already present")
	}

	// File content must not change.
	data, _ := os.ReadFile(path) // #nosec G304 -- test file path from t.TempDir()
	if string(data) != initial {
		t.Errorf("file should be unchanged; got:\n%s\nwant:\n%s", data, initial)
	}
}

func TestEnsureCgroupMemoryMissingFileIsNoop(t *testing.T) {
	// If cmdline.txt doesn't exist (non-RPi hardware or CI), the function
	// must silently return (false, nil) rather than error.
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent", "cmdline.txt")

	changed, err := ensureCgroupMemoryAt(path)
	if err != nil {
		t.Errorf("expected nil error for missing file, got: %v", err)
	}
	if changed {
		t.Error("expected changed=false for missing file")
	}
}

func TestEnsureCgroupMemoryOnlyAddsMissingParam(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cmdline.txt")

	// Only cgroup_memory=1 is present; cgroup_enable=memory is missing.
	initial := "console=tty1 cgroup_memory=1 rootwait\n"
	if err := os.WriteFile(path, []byte(initial), 0644); err != nil { // #nosec G306 -- test file in t.TempDir()
		t.Fatalf("write cmdline: %v", err)
	}

	changed, err := ensureCgroupMemoryAt(path)
	if err != nil {
		t.Fatalf("ensureCgroupMemoryAt: %v", err)
	}
	if !changed {
		t.Error("expected changed=true when cgroup_enable=memory is absent")
	}

	data, _ := os.ReadFile(path) // #nosec G304 -- test file path from t.TempDir()
	content := string(data)
	if !strings.Contains(content, "cgroup_enable=memory") {
		t.Errorf("cgroup_enable=memory not added:\n%s", content)
	}
	// cgroup_memory=1 must not be duplicated.
	if strings.Count(content, "cgroup_memory=1") != 1 {
		t.Errorf("cgroup_memory=1 duplicated:\n%s", content)
	}
}

func TestEnsureCgroupMemoryPreservesExistingContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cmdline.txt")

	initial := "console=serial0,115200 console=tty1 root=PARTUUID=573ee8d8-02 rootfstype=ext4 fsck.repair=yes rootwait\n"
	if err := os.WriteFile(path, []byte(initial), 0644); err != nil { // #nosec G306 -- test file in t.TempDir()
		t.Fatalf("write cmdline: %v", err)
	}

	_, err := ensureCgroupMemoryAt(path)
	if err != nil {
		t.Fatalf("ensureCgroupMemoryAt: %v", err)
	}

	data, _ := os.ReadFile(path) // #nosec G304 -- test file path from t.TempDir()
	content := string(data)

	// All original parameters must still be present.
	for _, param := range []string{"console=serial0,115200", "console=tty1", "rootfstype=ext4", "fsck.repair=yes", "rootwait"} {
		if !strings.Contains(content, param) {
			t.Errorf("original param %q lost from cmdline.txt:\n%s", param, content)
		}
	}
}
