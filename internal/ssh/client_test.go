// Copyright 2026 Ihor Dvoretskyi
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// genHostKey generates a fresh ed25519 host key pair for use in tests.
func genHostKey(t *testing.T) (gossh.PublicKey, gossh.Signer) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	pubKey, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("ssh.NewSignerFromKey: %v", err)
	}
	return pubKey, signer
}

// fakeAddr implements net.Addr for use as the remote parameter in callbacks.
type fakeAddr struct{ addr string }

func (f fakeAddr) Network() string { return "tcp" }
func (f fakeAddr) String() string  { return f.addr }

const testHost = "raspberrypi.local"
const testAddr = "raspberrypi.local:22"

// knownHostsWithKey writes a single known_hosts entry to a temp file and
// returns the file path. hostname should be the plain host (no port).
func knownHostsWithKey(t *testing.T, hostname string, key gossh.PublicKey) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	// knownhosts.Normalize strips :22, so we pass host:22 and let it normalize.
	line := knownhosts.Line([]string{knownhosts.Normalize(hostname + ":22")}, key)
	if err := os.WriteFile(path, []byte(line+"\n"), 0600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	return path
}

// emptyKnownHosts writes an empty known_hosts file and returns the path.
func emptyKnownHosts(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(path, []byte{}, 0600); err != nil {
		t.Fatalf("write empty known_hosts: %v", err)
	}
	return path
}

func TestBuildHostKeyCallback_StrictUnknownHost(t *testing.T) {
	knownKey, _ := genHostKey(t)
	_ = knownKey

	// File exists but is empty — host is unknown.
	khFile := emptyKnownHosts(t)
	presentedKey, _ := genHostKey(t)

	cb, err := buildHostKeyCallback(testHost, khFile, true /* strict */)
	if err != nil {
		t.Fatalf("buildHostKeyCallback: %v", err)
	}

	err = cb(testAddr, fakeAddr{"192.168.1.1:22"}, presentedKey)
	if err == nil {
		t.Fatal("expected error for unknown host in strict mode, got nil")
	}
	if !strings.Contains(err.Error(), "unknown SSH host") {
		t.Errorf("expected 'unknown SSH host' in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "ssh-keyscan") {
		t.Errorf("expected 'ssh-keyscan' hint in error, got: %v", err)
	}

	// File must remain empty — no TOFU append in strict mode.
	data, _ := os.ReadFile(khFile)
	if len(strings.TrimSpace(string(data))) > 0 {
		t.Errorf("strict mode must not append to known_hosts; got: %s", data)
	}
}

func TestBuildHostKeyCallback_TOFUUnknownHostAcceptsAndPersists(t *testing.T) {
	khFile := emptyKnownHosts(t)
	presentedKey, _ := genHostKey(t)

	cb, err := buildHostKeyCallback(testHost, khFile, false /* TOFU */)
	if err != nil {
		t.Fatalf("buildHostKeyCallback: %v", err)
	}

	// First call — host unknown, TOFU should accept and persist.
	if err := cb(testAddr, fakeAddr{"192.168.1.1:22"}, presentedKey); err != nil {
		t.Fatalf("TOFU first call should succeed, got: %v", err)
	}

	// The key must now be in the file.
	data, err := os.ReadFile(khFile)
	if err != nil {
		t.Fatalf("read known_hosts: %v", err)
	}
	if !strings.Contains(string(data), "ssh-ed25519") {
		t.Errorf("expected key to be persisted in known_hosts; got: %s", data)
	}

	// Second call — host is now known, same key should still be accepted.
	cb2, err := buildHostKeyCallback(testHost, khFile, false)
	if err != nil {
		t.Fatalf("buildHostKeyCallback (second): %v", err)
	}
	if err := cb2(testAddr, fakeAddr{"192.168.1.1:22"}, presentedKey); err != nil {
		t.Fatalf("TOFU second call (known host) should succeed, got: %v", err)
	}
}

func TestBuildHostKeyCallback_StrictKnownHostMatches(t *testing.T) {
	presentedKey, _ := genHostKey(t)
	khFile := knownHostsWithKey(t, testHost, presentedKey)

	cb, err := buildHostKeyCallback(testHost, khFile, true /* strict */)
	if err != nil {
		t.Fatalf("buildHostKeyCallback: %v", err)
	}

	if err := cb(testAddr, fakeAddr{"192.168.1.1:22"}, presentedKey); err != nil {
		t.Fatalf("strict mode with matching known host should succeed, got: %v", err)
	}
}

func TestBuildHostKeyCallback_TOFUKnownHostMatches(t *testing.T) {
	presentedKey, _ := genHostKey(t)
	khFile := knownHostsWithKey(t, testHost, presentedKey)

	cb, err := buildHostKeyCallback(testHost, khFile, false /* TOFU */)
	if err != nil {
		t.Fatalf("buildHostKeyCallback: %v", err)
	}

	if err := cb(testAddr, fakeAddr{"192.168.1.1:22"}, presentedKey); err != nil {
		t.Fatalf("TOFU mode with matching known host should succeed, got: %v", err)
	}
}

func TestBuildHostKeyCallback_MismatchRejectedInStrictMode(t *testing.T) {
	storedKey, _ := genHostKey(t)
	differentKey, _ := genHostKey(t)
	khFile := knownHostsWithKey(t, testHost, storedKey)

	cb, err := buildHostKeyCallback(testHost, khFile, true /* strict */)
	if err != nil {
		t.Fatalf("buildHostKeyCallback: %v", err)
	}

	err = cb(testAddr, fakeAddr{"192.168.1.1:22"}, differentKey)
	if err == nil {
		t.Fatal("expected error for mismatched key in strict mode, got nil")
	}
	if !strings.Contains(err.Error(), "host-key mismatch") {
		t.Errorf("expected 'host-key mismatch' in error, got: %v", err)
	}
}

func TestBuildHostKeyCallback_MismatchRejectedInTOFUMode(t *testing.T) {
	storedKey, _ := genHostKey(t)
	differentKey, _ := genHostKey(t)
	khFile := knownHostsWithKey(t, testHost, storedKey)

	cb, err := buildHostKeyCallback(testHost, khFile, false /* TOFU */)
	if err != nil {
		t.Fatalf("buildHostKeyCallback: %v", err)
	}

	err = cb(testAddr, fakeAddr{"192.168.1.1:22"}, differentKey)
	if err == nil {
		t.Fatal("expected error for mismatched key in TOFU mode, got nil")
	}
	if !strings.Contains(err.Error(), "host-key mismatch") {
		t.Errorf("expected 'host-key mismatch' in error, got: %v", err)
	}

	// File must NOT be modified — no overwrite of an existing entry.
	data, _ := os.ReadFile(khFile)
	if strings.Count(string(data), "ssh-ed25519") != 1 {
		t.Errorf("known_hosts should still contain exactly 1 key after mismatch; got:\n%s", data)
	}
}

func TestBuildHostKeyCallback_CreatesKnownHostsFileIfAbsent(t *testing.T) {
	dir := t.TempDir()
	khFile := filepath.Join(dir, "subdir", "known_hosts") // subdir does not exist yet

	presentedKey, _ := genHostKey(t)

	cb, err := buildHostKeyCallback(testHost, khFile, false /* TOFU */)
	if err != nil {
		t.Fatalf("buildHostKeyCallback should create missing file, got: %v", err)
	}

	if _, err := os.Stat(khFile); err != nil {
		t.Fatalf("known_hosts file should have been created, stat: %v", err)
	}

	// TOFU should accept and persist.
	if err := cb(testAddr, fakeAddr{"192.168.1.1:22"}, presentedKey); err != nil {
		t.Fatalf("TOFU with newly created file should succeed, got: %v", err)
	}
}

func TestBuildHostKeyCallback_StrictMissingFileErrors(t *testing.T) {
	dir := t.TempDir()
	khFile := filepath.Join(dir, "known_hosts")
	// File does not exist; ensureKnownHostsFile will create it,
	// but the host is unknown in strict mode — should error on callback.

	presentedKey, _ := genHostKey(t)

	cb, err := buildHostKeyCallback(testHost, khFile, true)
	if err != nil {
		t.Fatalf("buildHostKeyCallback: %v", err)
	}

	err = cb(testAddr, fakeAddr{"192.168.1.1:22"}, presentedKey)
	if err == nil {
		t.Fatal("expected error: strict mode + empty file + unknown host")
	}
	if !strings.Contains(err.Error(), "unknown SSH host") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Compile-time check: fakeAddr implements net.Addr.
var _ net.Addr = fakeAddr{}
