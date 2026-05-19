// Copyright 2026 Ihor Dvoretskyi
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package orchestrator

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

// withLookup temporarily replaces the package-level lookupHost so tests can
// feed deterministic address lists to resolveToIP. It restores the original on
// test cleanup.
func withLookup(t *testing.T, fn func(host string) ([]string, error)) {
	t.Helper()
	orig := lookupHost
	lookupHost = fn
	t.Cleanup(func() { lookupHost = orig })
}

// TestResolveToIPReturnsSelf_AlreadyIPv4 verifies that an IPv4 literal is
// returned untouched and never goes through DNS.
func TestResolveToIPReturnsSelf_AlreadyIPv4(t *testing.T) {
	withLookup(t, func(string) ([]string, error) {
		t.Fatal("lookup must not be called for a literal IPv4 address")
		return nil, nil
	})
	got := resolveToIP("192.168.1.254")
	if got != "192.168.1.254" {
		t.Errorf("resolveToIP(IPv4) = %q, want %q", got, "192.168.1.254")
	}
}

// TestResolveToIPReturnsSelf_AlreadyIPv6 verifies that an IPv6 literal is
// returned untouched and never goes through DNS.
func TestResolveToIPReturnsSelf_AlreadyIPv6(t *testing.T) {
	withLookup(t, func(string) ([]string, error) {
		t.Fatal("lookup must not be called for a literal IPv6 address")
		return nil, nil
	})
	got := resolveToIP("::1")
	if got != "::1" {
		t.Errorf("resolveToIP(::1) = %q, want %q", got, "::1")
	}
}

// TestResolveToIPReturnsSelf_UnresolvableHost asserts that a hostname which
// fails to resolve is returned unchanged (no panic, no empty string).
func TestResolveToIPReturnsSelf_UnresolvableHost(t *testing.T) {
	withLookup(t, func(string) ([]string, error) {
		return nil, fmt.Errorf("no such host")
	})
	got := resolveToIP("this.host.does.not.exist.invalid")
	if got != "this.host.does.not.exist.invalid" {
		t.Errorf("unresolvable host: got %q, want original hostname", got)
	}
}

// TestResolveToIPFiltersLinkLocal verifies that an IPv6 link-local result is
// skipped in favor of an IPv4 address from the same lookup. This protects
// macOS users whose mDNS returns fe80:: addresses for .local hosts.
func TestResolveToIPFiltersLinkLocal(t *testing.T) {
	withLookup(t, func(host string) ([]string, error) {
		if host != "rpi.local" {
			t.Fatalf("unexpected host %q", host)
		}
		return []string{"fe80::1", "192.168.1.100"}, nil
	})
	got := resolveToIP("rpi.local")
	if got != "192.168.1.100" {
		t.Errorf("link-local filter: got %q, want 192.168.1.100", got)
	}
}

// TestResolveToIPPrefersIPv4OverIPv6 ensures IPv4 wins over a global IPv6
// even when the IPv6 is returned first.
func TestResolveToIPPrefersIPv4OverIPv6(t *testing.T) {
	withLookup(t, func(string) ([]string, error) {
		return []string{"2001:db8::1", "10.0.0.5"}, nil
	})
	got := resolveToIP("rpi.local")
	if got != "10.0.0.5" {
		t.Errorf("IPv4 preference: got %q, want 10.0.0.5", got)
	}
}

// TestResolveToIPFallsBackToGlobalIPv6 confirms that when no IPv4 is available
// and no link-local IPv6 is present, a global IPv6 is returned as the
// fallback (this is what kubeconfig will then bracket via net.JoinHostPort).
func TestResolveToIPFallsBackToGlobalIPv6(t *testing.T) {
	withLookup(t, func(string) ([]string, error) {
		return []string{"fe80::1", "2001:db8::1"}, nil
	})
	got := resolveToIP("rpi.local")
	if got != "2001:db8::1" {
		t.Errorf("IPv6 fallback: got %q, want 2001:db8::1", got)
	}
}

// TestResolveToIPLocalhostIsIPv4 uses the real system resolver against
// "localhost" — this should never return a link-local address on any sane
// system. If the system has unusual DNS, the test simply verifies the result
// is not a link-local address.
func TestResolveToIPLocalhostIsIPv4(t *testing.T) {
	got := resolveToIP("localhost")
	if !strings.HasPrefix(got, "127.") && got != "localhost" && got != "::1" {
		ip := net.ParseIP(got)
		if ip != nil && ip.IsLinkLocalUnicast() {
			t.Errorf("resolveToIP(localhost) returned link-local address: %s", got)
		}
	}
}
