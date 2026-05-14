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

// TestUpdateHostsFileAddsEntry verifies that updateHostsFile creates
// a 127.0.1.1 entry when none exists. Without this fix, sudo prints
// "unable to resolve host <newhostname>: No address associated with hostname"
// after every hostnamectl set-hostname call, polluting stderr and
// causing confusing log output.
func TestUpdateHostsFileAddsEntry(t *testing.T) {
	dir := t.TempDir()
	hostsPath := filepath.Join(dir, "hosts")

	initial := "127.0.0.1\tlocalhost\n::1\tlocalhost\n"
	if err := os.WriteFile(hostsPath, []byte(initial), 0644); err != nil {
		t.Fatalf("write hosts: %v", err)
	}

	// Temporarily swap the path (we test the logic directly by calling the
	// underlying helper with a custom path via a thin wrapper).
	if err := updateHostsFileAt(hostsPath, "newhostname"); err != nil {
		t.Fatalf("updateHostsFileAt: %v", err)
	}

	data, err := os.ReadFile(hostsPath)
	if err != nil {
		t.Fatalf("read hosts: %v", err)
	}
	content := string(data)

	if !strings.Contains(content, "127.0.1.1") {
		t.Errorf("expected 127.0.1.1 entry in hosts, got:\n%s", content)
	}
	if !strings.Contains(content, "newhostname") {
		t.Errorf("expected 'newhostname' in hosts, got:\n%s", content)
	}
}

func TestUpdateHostsFileReplacesExistingEntry(t *testing.T) {
	dir := t.TempDir()
	hostsPath := filepath.Join(dir, "hosts")

	initial := "127.0.0.1\tlocalhost\n127.0.1.1\toldhostname\n"
	if err := os.WriteFile(hostsPath, []byte(initial), 0644); err != nil {
		t.Fatalf("write hosts: %v", err)
	}

	if err := updateHostsFileAt(hostsPath, "newhostname"); err != nil {
		t.Fatalf("updateHostsFileAt: %v", err)
	}

	data, _ := os.ReadFile(hostsPath)
	content := string(data)

	if strings.Contains(content, "oldhostname") {
		t.Errorf("old hostname should have been replaced, got:\n%s", content)
	}
	if !strings.Contains(content, "newhostname") {
		t.Errorf("new hostname not found in hosts, got:\n%s", content)
	}
	// Must not duplicate the 127.0.1.1 line.
	count := strings.Count(content, "127.0.1.1")
	if count != 1 {
		t.Errorf("expected exactly 1 127.0.1.1 line, got %d:\n%s", count, content)
	}
}

func TestUpdateHostsFileIdempotent(t *testing.T) {
	dir := t.TempDir()
	hostsPath := filepath.Join(dir, "hosts")

	initial := "127.0.0.1\tlocalhost\n127.0.1.1\tsamehost\n"
	if err := os.WriteFile(hostsPath, []byte(initial), 0644); err != nil {
		t.Fatalf("write hosts: %v", err)
	}

	for i := 0; i < 3; i++ {
		if err := updateHostsFileAt(hostsPath, "samehost"); err != nil {
			t.Fatalf("updateHostsFileAt (run %d): %v", i+1, err)
		}
	}

	data, _ := os.ReadFile(hostsPath)
	content := string(data)

	count := strings.Count(content, "127.0.1.1")
	if count != 1 {
		t.Errorf("idempotent: expected 1 127.0.1.1 line after 3 runs, got %d:\n%s", count, content)
	}
}
