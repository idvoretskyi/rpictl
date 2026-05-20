// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT
package config

import (
	"testing"
)

func TestDetectProfile(t *testing.T) {
	cases := []struct {
		model   string
		want    string
	}{
		{"Raspberry Pi 3 Model B Rev 1.2", "rpi3"},
		{"Raspberry Pi 3 Model B Plus Rev 1.3", "rpi3b-plus"},
		{"Raspberry Pi 4 Model B Rev 1.4", "rpi4"},
		{"Raspberry Pi 5 Model B Rev 1.0", "rpi5"},
		{"Some Other Board", "unknown"},
	}
	for _, tc := range cases {
		got := DetectProfile(tc.model)
		if got != tc.want {
			t.Errorf("DetectProfile(%q) = %q, want %q", tc.model, got, tc.want)
		}
	}
}

func TestGetProfile(t *testing.T) {
	for _, name := range []string{"rpi3", "rpi3b-plus", "rpi4", "rpi5"} {
		p, ok := GetProfile(name)
		if !ok {
			t.Errorf("GetProfile(%q) not found", name)
			continue
		}
		if p.Name != name {
			t.Errorf("GetProfile(%q).Name = %q", name, p.Name)
		}
	}
	_, ok := GetProfile("nonexistent")
	if ok {
		t.Error("GetProfile(nonexistent) should return false")
	}
}

func TestApplyProfileDefaults(t *testing.T) {
	p, _ := GetProfile("rpi3b-plus")
	h := &Host{}
	applyProfileDefaults(h, &p)

	if h.Swap.ZRAMPercent == nil || *h.Swap.ZRAMPercent != 50 {
		t.Errorf("expected ZRAMPercent=50, got %v", h.Swap.ZRAMPercent)
	}
	if h.Swap.Swappiness == nil || *h.Swap.Swappiness != 60 {
		t.Errorf("expected Swappiness=60, got %v", h.Swap.Swappiness)
	}
	if h.GPUMemMB == nil || *h.GPUMemMB != 16 {
		t.Errorf("expected GPUMemMB=16, got %v", h.GPUMemMB)
	}
	if len(h.K3s.KubeletArgs) == 0 {
		t.Error("expected eviction-hard kubelet arg to be set")
	}
}
