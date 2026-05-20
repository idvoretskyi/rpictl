// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT
package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBackupFileIdempotent ensures backupFile is idempotent: calling it twice
// does not overwrite the first backup.
func TestBackupFileIdempotent(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "test.conf")
	bak := original + ".bak.rpictl"

	allowHardeningPathForTest(original)

	// Write original content
	if err := os.WriteFile(original, []byte("original"), 0644); err != nil { // #nosec G306 -- test file in t.TempDir()
		t.Fatal(err)
	}

	// First backup
	if err := backupFile(original); err != nil {
		t.Fatalf("first backup: %v", err)
	}
	// Overwrite original
	if err := os.WriteFile(original, []byte("modified"), 0644); err != nil { // #nosec G306 -- test file in t.TempDir()
		t.Fatal(err)
	}
	// Second backup — should NOT overwrite the first
	if err := backupFile(original); err != nil {
		t.Fatalf("second backup: %v", err)
	}

	data, err := os.ReadFile(bak) // #nosec G304 -- test file path from t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "original" {
		t.Errorf("backup content = %q, want %q", string(data), "original")
	}
}

// TestRestoreFile ensures restoreFile restores the original and removes the backup.
func TestRestoreFile(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "test.conf")
	bak := original + ".bak.rpictl"

	allowHardeningPathForTest(original)

	if err := os.WriteFile(original, []byte("original"), 0644); err != nil { // #nosec G306 -- test file in t.TempDir()
		t.Fatal(err)
	}
	if err := backupFile(original); err != nil {
		t.Fatal(err)
	}
	// Overwrite
	if err := os.WriteFile(original, []byte("modified"), 0644); err != nil { // #nosec G306 -- test file in t.TempDir()
		t.Fatal(err)
	}
	// Restore
	if err := restoreFile(original); err != nil {
		t.Fatalf("restore: %v", err)
	}
	data, err := os.ReadFile(original) // #nosec G304 -- test file path from t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "original" {
		t.Errorf("restored content = %q, want %q", string(data), "original")
	}
	// Backup should be gone
	if _, err := os.Stat(bak); !os.IsNotExist(err) {
		t.Error("backup file should have been removed after restore")
	}
}

// TestWriteAtomic verifies atomic write and mode preservation.
func TestWriteAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "conf")

	allowHardeningPathForTest(path)

	// Create with specific mode
	if err := os.WriteFile(path, []byte("old"), 0640); err != nil { // #nosec G306 -- test file in t.TempDir()
		t.Fatal(err)
	}
	if err := writeAtomic(path, "new", 0600); err != nil {
		t.Fatalf("writeAtomic: %v", err)
	}
	data, _ := os.ReadFile(path) // #nosec G304 -- test file path from t.TempDir()
	if string(data) != "new" {
		t.Errorf("content = %q, want %q", string(data), "new")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0640 {
		t.Errorf("mode = %o, want 0640 (preserved from original)", info.Mode().Perm())
	}
}

// TestSysctlHardeningContentNoIPForward ensures the sysctl content never
// sets ip_forward or bridge-nf-call (required by k3s/flannel).
// Comments mentioning them are fine; actual key=value assignments must not appear.
func TestSysctlHardeningContentNoIPForward(t *testing.T) {
	// Check that no non-comment line sets ip_forward or bridge-nf-call
	for _, line := range strings.Split(sysctlHardeningContent, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "net.ipv4.ip_forward") {
			t.Errorf("sysctl hardening must NOT set net.ipv4.ip_forward — k3s requires it: %q", line)
		}
		if strings.Contains(trimmed, "bridge-nf-call") {
			t.Errorf("sysctl hardening must NOT set bridge-nf-call — k3s requires it: %q", line)
		}
	}
}

// TestSysctlHardeningContentRequiredKeys checks that key hardening values are present.
func TestSysctlHardeningContentRequiredKeys(t *testing.T) {
	required := []string{
		"kernel.kptr_restrict",
		"kernel.dmesg_restrict",
		"net.ipv4.tcp_syncookies",
		"fs.protected_hardlinks",
		"fs.protected_symlinks",
	}
	for _, key := range required {
		if !strings.Contains(sysctlHardeningContent, key) {
			t.Errorf("sysctl hardening content missing required key %q", key)
		}
	}
}

// TestHardeningMarkerRoundtrip verifies write/exists/remove cycle.
// Skipped if /var/lib/rpictl cannot be created (not running as root on a Pi).
func TestHardeningMarkerRoundtrip(t *testing.T) {
	layer := "test-layer-roundtrip"
	hash := "abc123"

	if err := os.MkdirAll(hardeningMarkerDir, 0750); err != nil {
		t.Skipf("skipping: cannot create %s (not root): %v", hardeningMarkerDir, err)
	}
	realPath := hardeningLayerMarkerPath(layer)
	_ = os.Remove(realPath)
	defer func() { _ = os.Remove(realPath) }()

	if hardeningMarkerExists(layer, hash) {
		t.Fatal("marker should not exist before write")
	}
	writeHardeningMarker(layer, hash)

	if !hardeningMarkerExists(layer, hash) {
		t.Error("marker should exist after write")
	}
	if hardeningMarkerExists(layer, "different-hash") {
		t.Error("marker should not match a different hash")
	}

	removeHardeningMarker(layer)
	if hardeningMarkerExists(layer, hash) {
		t.Error("marker should not exist after remove")
	}
}

// TestAddMountOptions verifies mount option deduplication and addition.
func TestAddMountOptions(t *testing.T) {
	cases := []struct {
		existing string
		add      []string
		want     string
	}{
		{"defaults", []string{"noexec", "nosuid"}, "defaults,noexec,nosuid"},
		{"defaults,noexec", []string{"noexec", "nosuid"}, "defaults,noexec,nosuid"},
		{"nodev,nosuid,noexec", []string{"nodev", "nosuid", "noexec"}, "nodev,nosuid,noexec"},
		{"", []string{"noexec"}, "defaults,noexec"},
	}
	for _, tc := range cases {
		got := addMountOptions(tc.existing, tc.add)
		if got != tc.want {
			t.Errorf("addMountOptions(%q, %v) = %q, want %q", tc.existing, tc.add, got, tc.want)
		}
	}
}

// TestContainsMountPresent / NotPresent
func TestContainsMount(t *testing.T) {
	fstab := []string{
		"tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec 0 0",
		"# /var/tmp is not mounted",
	}
	if !containsMount(fstab, "/tmp") {
		t.Error("expected /tmp to be found in fstab")
	}
	if containsMount(fstab, "/var/tmp") {
		t.Error("expected /var/tmp NOT to be found in fstab")
	}
}

// TestBoolToYesNo
func TestBoolToYesNo(t *testing.T) {
	if boolToYesNo(true) != "yes" {
		t.Error("expected yes")
	}
	if boolToYesNo(false) != "no" {
		t.Error("expected no")
	}
}

// TestParseSshdT verifies the sshd -T output parser.
func TestParseSshdT(t *testing.T) {
	input := `passwordauthentication no
permitrootlogin no
usedns no
port 22
`
	m := parseSshdT(input)
	checks := map[string]string{
		"passwordauthentication": "no",
		"permitrootlogin":        "no",
		"usedns":                 "no",
		"port":                   "22",
	}
	for k, want := range checks {
		if got := m[k]; got != want {
			t.Errorf("parseSshdT[%q] = %q, want %q", k, got, want)
		}
	}
}

// TestMountHasOption
func TestMountHasOption(t *testing.T) {
	mounts := "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime 0 0\ntmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\n"
	if !mountHasOption(mounts, "/tmp", "noexec") {
		t.Error("/tmp should have noexec")
	}
	if mountHasOption(mounts, "/dev/shm", "noexec") {
		t.Error("/dev/shm should NOT have noexec in this test data")
	}
}

// TestParseSimpleYAML verifies k3s config YAML parsing.
func TestParseSimpleYAML(t *testing.T) {
	input := `# comment
protect-kernel-defaults: true
kube-apiserver-arg:
  - audit-log-path=/var/log/k3s-audit.log
  - audit-log-maxage=30
`
	m := parseSimpleYAML(input)
	if v, ok := m["protect-kernel-defaults"]; !ok || v != true {
		t.Errorf("protect-kernel-defaults = %v, want true", v)
	}
	args, ok := m["kube-apiserver-arg"].([]string)
	if !ok || len(args) != 2 {
		t.Errorf("kube-apiserver-arg = %v, want 2 items", m["kube-apiserver-arg"])
	}
}

// TestReplaceOrAppendConf verifies auditd conf modification.
func TestReplaceOrAppendConf(t *testing.T) {
	content := "max_log_file = 8\nother = value\n"
	result := replaceOrAppendConf(content, "max_log_file", "50")
	if !strings.Contains(result, "max_log_file = 50") {
		t.Errorf("expected max_log_file = 50 in result: %q", result)
	}
	if strings.Contains(result, "max_log_file = 8") {
		t.Error("old value should be replaced")
	}
	// Append new key
	result2 := replaceOrAppendConf(content, "num_logs", "7")
	if !strings.Contains(result2, "num_logs = 7") {
		t.Errorf("expected num_logs = 7 appended: %q", result2)
	}
}

// TestEncodeVerifyReport ensures JSON report is well-formed.
func TestEncodeVerifyReport(t *testing.T) {
	r := &HardenVerifyReport{
		Level: "standard",
		Controls: []VerifyControl{
			{Name: "ssh:passwordauthentication", Pass: true, Detail: "want=no got=no"},
			{Name: "sysctl:net.ipv4.tcp_syncookies", Pass: false, Detail: "want=1 got=0"},
		},
		Pass: 1, Fail: 1, Total: 2,
	}
	json := encodeVerifyReport(r)
	if !strings.Contains(json, `"level":"standard"`) {
		t.Errorf("missing level in report: %s", json)
	}
	if !strings.Contains(json, `"pass":1`) {
		t.Errorf("missing pass count: %s", json)
	}
	if !strings.Contains(json, `"fail":1`) {
		t.Errorf("missing fail count: %s", json)
	}
	if !strings.Contains(json, `"controls":[`) {
		t.Errorf("missing controls array: %s", json)
	}
}
