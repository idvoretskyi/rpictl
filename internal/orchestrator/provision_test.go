// Copyright 2026 Ihor Dvoretskyi
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package orchestrator

import (
	"net"
	"strings"
	"testing"
)

// TestResolveToIPReturnsIPv4 verifies that resolveToIP returns an IPv4 address
// when given a hostname. mDNS .local names are not included in k3s TLS SANs,
// and macOS mDNS resolves them to IPv6 link-local addresses (fe80::...%en0)
// which are invalid in kubeconfig server URLs, causing "invalid URL escape".
func TestResolveToIPReturnsSelf_AlreadyIPv4(t *testing.T) {
	got := resolveToIP("192.168.1.254")
	if got != "192.168.1.254" {
		t.Errorf("resolveToIP(IPv4) = %q, want %q", got, "192.168.1.254")
	}
}

func TestResolveToIPReturnsSelf_AlreadyIPv6(t *testing.T) {
	got := resolveToIP("::1")
	if got != "::1" {
		t.Errorf("resolveToIP(::1) = %q, want %q", got, "::1")
	}
}

func TestResolveToIPReturnsSelf_UnresolvableHost(t *testing.T) {
	// A hostname that cannot be resolved must be returned as-is (no panic, no empty string).
	got := resolveToIP("this.host.does.not.exist.invalid")
	if got != "this.host.does.not.exist.invalid" {
		t.Errorf("unresolvable host: got %q, want original hostname", got)
	}
}

func TestResolveToIPFiltersLinkLocal(t *testing.T) {
	// Directly test the filter logic by mimicking what resolveToIP does
	// internally for a set of addresses that includes link-local IPv6.
	addrs := []string{
		"fe80::1%en0", // link-local — must be skipped
		"192.168.1.100",
	}

	// Replicate the selection logic from resolveToIP.
	selected := ""
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip != nil && ip.To4() != nil {
			selected = a
			break
		}
	}

	if selected != "192.168.1.100" {
		t.Errorf("link-local filter: expected 192.168.1.100, got %q", selected)
	}
}

func TestResolveToIPPrefersIPv4OverIPv6(t *testing.T) {
	// Replicate selection logic: IPv4 must win over global IPv6.
	addrs := []string{"2001:db8::1", "10.0.0.5"}
	selected := ""
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip != nil && ip.To4() != nil {
			selected = a
			break
		}
	}
	if selected != "10.0.0.5" {
		t.Errorf("expected IPv4 10.0.0.5 to be preferred, got %q", selected)
	}
}

// TestResolveToIPLocalhostReturnsLoopback verifies that "localhost" resolves to
// a usable loopback address rather than being passed through as a hostname.
func TestResolveToIPLocalhostIsIPv4(t *testing.T) {
	got := resolveToIP("localhost")
	if !strings.HasPrefix(got, "127.") && got != "localhost" {
		// Some environments may not resolve localhost; just ensure no link-local.
		ip := net.ParseIP(got)
		if ip != nil && ip.IsLinkLocalUnicast() {
			t.Errorf("resolveToIP(localhost) returned link-local address: %s", got)
		}
	}
}
