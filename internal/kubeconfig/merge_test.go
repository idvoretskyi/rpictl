// Copyright 2026 Ihor Dvoretskyi
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package kubeconfig

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

const sampleSrc = `apiVersion: v1
kind: Config
current-context: rpi3bplus
clusters:
- name: rpi3bplus
  cluster:
    server: https://192.168.1.254:6443
    certificate-authority-data: AAAA
contexts:
- name: rpi3bplus
  context:
    cluster: rpi3bplus
    user: rpi3bplus
users:
- name: rpi3bplus
  user:
    client-certificate-data: BBBB
    client-key-data: CCCC
`

const existingDst = `apiVersion: v1
kind: Config
current-context: docker-desktop
clusters:
- name: docker-desktop
  cluster:
    server: https://kubernetes.docker.internal:6443
contexts:
- name: docker-desktop
  context:
    cluster: docker-desktop
    user: docker-desktop
users:
- name: docker-desktop
  user:
    client-certificate-data: ZZZZ
`

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func loadKC(t *testing.T, path string) *kubeconfigFile {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- test file path from t.TempDir()
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var kc kubeconfigFile
	if err := yaml.Unmarshal(data, &kc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	return &kc
}

func TestMergeIntoMissingFileCreatesIt(t *testing.T) {
	dir := t.TempDir()
	src := writeFile(t, dir, "src.yaml", sampleSrc)
	dst := filepath.Join(dir, "subdir", "config")

	if err := Merge(src, dst, "rpi3bplus", true); err != nil {
		t.Fatalf("Merge: %v", err)
	}

	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("expected 0600, got %o", perm)
	}

	kc := loadKC(t, dst)
	if kc.CurrentContext != "rpi3bplus" {
		t.Errorf("current-context = %q, want rpi3bplus", kc.CurrentContext)
	}
	if len(kc.Clusters) != 1 || kc.Clusters[0].Name != "rpi3bplus" {
		t.Errorf("clusters = %+v", kc.Clusters)
	}
	if len(kc.Contexts) != 1 || kc.Contexts[0].Name != "rpi3bplus" {
		t.Errorf("contexts = %+v", kc.Contexts)
	}
	if len(kc.Users) != 1 || kc.Users[0].Name != "rpi3bplus" {
		t.Errorf("users = %+v", kc.Users)
	}
}

func TestMergeIntoExistingPreservesOtherContexts(t *testing.T) {
	dir := t.TempDir()
	src := writeFile(t, dir, "src.yaml", sampleSrc)
	dst := writeFile(t, dir, "config", existingDst)

	if err := Merge(src, dst, "rpi3bplus", false); err != nil {
		t.Fatalf("Merge: %v", err)
	}

	kc := loadKC(t, dst)
	if kc.CurrentContext != "docker-desktop" {
		t.Errorf("current-context must be preserved, got %q", kc.CurrentContext)
	}

	names := func(es []namedYAMLEntry) []string {
		var out []string
		for _, e := range es {
			out = append(out, e.Name)
		}
		return out
	}
	got := names(kc.Contexts)
	wantHas := map[string]bool{"docker-desktop": false, "rpi3bplus": false}
	for _, n := range got {
		if _, ok := wantHas[n]; ok {
			wantHas[n] = true
		}
	}
	for n, ok := range wantHas {
		if !ok {
			t.Errorf("context %q missing after merge; got %v", n, got)
		}
	}
}

func TestMergeReplacesSameNamedContext(t *testing.T) {
	dir := t.TempDir()

	// Pre-existing dst already has rpi3bplus pointing at an old IP.
	oldDst := `apiVersion: v1
kind: Config
current-context: rpi3bplus
clusters:
- name: rpi3bplus
  cluster:
    server: https://10.0.0.1:6443
contexts:
- name: rpi3bplus
  context:
    cluster: rpi3bplus
    user: rpi3bplus
users:
- name: rpi3bplus
  user:
    client-certificate-data: OLD
`
	src := writeFile(t, dir, "src.yaml", sampleSrc)
	dst := writeFile(t, dir, "config", oldDst)

	if err := Merge(src, dst, "rpi3bplus", true); err != nil {
		t.Fatalf("Merge: %v", err)
	}

	kc := loadKC(t, dst)
	if len(kc.Clusters) != 1 {
		t.Fatalf("expected 1 cluster after replace, got %d", len(kc.Clusters))
	}

	// Serialize the cluster node and ensure the new server IP is present
	// and the old one is gone.
	data, err := yaml.Marshal(kc.Clusters[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(data)
	if !contains(s, "192.168.1.254") {
		t.Errorf("expected new server IP in merged cluster, got: %s", s)
	}
	if contains(s, "10.0.0.1") {
		t.Errorf("expected old server IP to be removed, got: %s", s)
	}
}

func TestMergePreservesDestinationFileMode(t *testing.T) {
	dir := t.TempDir()
	src := writeFile(t, dir, "src.yaml", sampleSrc)
	dst := filepath.Join(dir, "config")
	if err := os.WriteFile(dst, []byte(existingDst), 0640); err != nil { // #nosec G306 -- test file in t.TempDir()
		t.Fatalf("write: %v", err)
	}

	if err := Merge(src, dst, "rpi3bplus", false); err != nil {
		t.Fatalf("Merge: %v", err)
	}

	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0640 {
		t.Errorf("expected mode to be preserved as 0640, got %o", perm)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
