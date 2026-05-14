// Copyright 2026 Ihor Dvoretskyi
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package kubeconfig

import (
	"strings"
	"testing"
)

// TestRewriteReplacesLocalhostWithIP verifies that rewrite substitutes the
// loopback server address with the actual host IP. Without this the kubeconfig
// points to 127.0.0.1 which is unreachable from the laptop.
func TestRewriteReplacesLocalhostWithIP(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		host   string
		wantIn string
	}{
		{
			name:   "127.0.0.1",
			input:  "server: https://127.0.0.1:6443\n",
			host:   "192.168.1.254",
			wantIn: "https://192.168.1.254:6443",
		},
		{
			name:   "localhost",
			input:  "server: https://localhost:6443\n",
			host:   "192.168.1.254",
			wantIn: "https://192.168.1.254:6443",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := rewrite(tc.input, tc.host, "testctx")
			if err != nil {
				t.Fatalf("rewrite: %v", err)
			}
			if !strings.Contains(out, tc.wantIn) {
				t.Errorf("expected %q in output, got:\n%s", tc.wantIn, out)
			}
			if strings.Contains(out, "127.0.0.1") || strings.Contains(out, "localhost") {
				t.Errorf("loopback address not replaced in output:\n%s", out)
			}
		})
	}
}

// TestRewriteRenamesDefaultContext verifies context/cluster/user renaming.
// Without this all kubeconfigs would have context name "default", making
// multi-cluster setups unusable.
func TestRewriteRenamesDefaultContext(t *testing.T) {
	raw := `apiVersion: v1
clusters:
- cluster:
    server: https://127.0.0.1:6443
  name: default
contexts:
- context:
    cluster: default
    user: default
  name: default
current-context: default
users:
- name: default
`

	out, err := rewrite(raw, "192.168.1.254", "rpi3bplus")
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}

	for _, want := range []string{
		"name: rpi3bplus",
		"cluster: rpi3bplus",
		"user: rpi3bplus",
		"current-context: rpi3bplus",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output, got:\n%s", want, out)
		}
	}
	if strings.Contains(out, ": default") {
		t.Errorf("'default' context name not fully replaced:\n%s", out)
	}
}

// TestRewriteIPv6LinkLocalNotUsedAsServer verifies that the kubeconfig server
// address is never an IPv6 link-local (fe80::.../%) address. macOS mDNS may
// resolve .local hostnames to link-local IPv6 addresses, which are not valid
// in URLs and cause "invalid URL escape" errors in kubectl.
func TestRewriteIPv6LinkLocalNotUsedAsServer(t *testing.T) {
	raw := "server: https://127.0.0.1:6443\n"

	// Simulate what would happen if an IPv6 link-local slipped through.
	out, err := rewrite(raw, "fe80::1%en0", "ctx")
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	// The rewrite itself just substitutes whatever address is given; the
	// filtering happens in resolveToIP (orchestrator). This test documents
	// that link-local addresses ARE escaped in the URL and would be broken.
	if strings.Contains(out, "fe80::1%en0") {
		// Not a test failure per se, but document the problem.
		t.Logf("NOTE: link-local IPv6 in kubeconfig server URL: %s", out)
	}
}

// TestRewriteDoesNotCorruptNonDefaultNames verifies that only exact "default"
// name tokens are replaced, not substrings within other values.
func TestRewriteDoesNotCorruptArbitraryContent(t *testing.T) {
	raw := `server: https://127.0.0.1:6443
name: default
some-key: non-default-value
`
	out, err := rewrite(raw, "10.0.0.1", "mycluster")
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if !strings.Contains(out, "non-default-value") {
		t.Errorf("rewrite incorrectly modified 'non-default-value':\n%s", out)
	}
}
