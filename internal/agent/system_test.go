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
	if err := os.WriteFile(hostsPath, []byte(initial), 0644); err != nil { // #nosec G306 -- test file in t.TempDir()
		t.Fatalf("write hosts: %v", err)
	}

	// Temporarily swap the path (we test the logic directly by calling the
	// underlying helper with a custom path via a thin wrapper).
	if err := updateHostsFileAt(hostsPath, "newhostname"); err != nil {
		t.Fatalf("updateHostsFileAt: %v", err)
	}

	data, err := os.ReadFile(hostsPath) // #nosec G304 -- test file path from t.TempDir()
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
	if err := os.WriteFile(hostsPath, []byte(initial), 0644); err != nil { // #nosec G306 -- test file in t.TempDir()
		t.Fatalf("write hosts: %v", err)
	}

	if err := updateHostsFileAt(hostsPath, "newhostname"); err != nil {
		t.Fatalf("updateHostsFileAt: %v", err)
	}

	data, _ := os.ReadFile(hostsPath) // #nosec G304 -- test file path from t.TempDir()
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
	if err := os.WriteFile(hostsPath, []byte(initial), 0644); err != nil { // #nosec G306 -- test file in t.TempDir()
		t.Fatalf("write hosts: %v", err)
	}

	for i := 0; i < 3; i++ {
		if err := updateHostsFileAt(hostsPath, "samehost"); err != nil {
			t.Fatalf("updateHostsFileAt (run %d): %v", i+1, err)
		}
	}

	data, _ := os.ReadFile(hostsPath) // #nosec G304 -- test file path from t.TempDir()
	content := string(data)

	count := strings.Count(content, "127.0.1.1")
	if count != 1 {
		t.Errorf("idempotent: expected 1 127.0.1.1 line after 3 runs, got %d:\n%s", count, content)
	}
}

// TestUpdateHostsFileDoesNotMatchPrefix verifies that the field-based match
// only replaces a line whose first field is exactly 127.0.1.1, never lines
// whose first field is e.g. 127.0.1.10 — a substring-prefix bug.
func TestUpdateHostsFileDoesNotMatchPrefix(t *testing.T) {
	dir := t.TempDir()
	hostsPath := filepath.Join(dir, "hosts")

	initial := "127.0.0.1\tlocalhost\n127.0.1.10\tunrelated.example\n"
	if err := os.WriteFile(hostsPath, []byte(initial), 0644); err != nil { // #nosec G306 -- test file in t.TempDir()
		t.Fatalf("write hosts: %v", err)
	}

	if err := updateHostsFileAt(hostsPath, "newhostname"); err != nil {
		t.Fatalf("updateHostsFileAt: %v", err)
	}

	data, _ := os.ReadFile(hostsPath) // #nosec G304 -- test file path from t.TempDir()
	content := string(data)

	if !strings.Contains(content, "127.0.1.10\tunrelated.example") {
		t.Errorf("127.0.1.10 line was incorrectly modified:\n%s", content)
	}
	if !strings.Contains(content, "127.0.1.1\tnewhostname") {
		t.Errorf("expected new 127.0.1.1 entry to be appended, got:\n%s", content)
	}
}

// TestUpdateHostsFileSkipsCommentedLine verifies that a commented-out
// "#127.0.1.1 ..." entry is not treated as the active mapping.
func TestUpdateHostsFileSkipsCommentedLine(t *testing.T) {
	dir := t.TempDir()
	hostsPath := filepath.Join(dir, "hosts")

	initial := "127.0.0.1\tlocalhost\n# 127.0.1.1 disabled\n"
	if err := os.WriteFile(hostsPath, []byte(initial), 0644); err != nil { // #nosec G306 -- test file in t.TempDir()
		t.Fatalf("write hosts: %v", err)
	}

	if err := updateHostsFileAt(hostsPath, "newhost"); err != nil {
		t.Fatalf("updateHostsFileAt: %v", err)
	}

	data, _ := os.ReadFile(hostsPath) // #nosec G304 -- test file path from t.TempDir()
	content := string(data)

	if !strings.Contains(content, "# 127.0.1.1 disabled") {
		t.Errorf("commented line was incorrectly modified:\n%s", content)
	}
	if !strings.Contains(content, "127.0.1.1\tnewhost") {
		t.Errorf("expected new active 127.0.1.1 entry, got:\n%s", content)
	}
}
