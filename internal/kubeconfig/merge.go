// Copyright 2026 Ihor Dvoretskyi
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package kubeconfig

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// kubeconfigFile is a minimal kubeconfig schema sufficient for merging.
// Unknown fields are preserved verbatim via yaml.Node.
type kubeconfigFile struct {
	APIVersion     string           `yaml:"apiVersion,omitempty"`
	Kind           string           `yaml:"kind,omitempty"`
	CurrentContext string           `yaml:"current-context,omitempty"`
	Preferences    *yaml.Node       `yaml:"preferences,omitempty"`
	Clusters       []namedYAMLEntry `yaml:"clusters"`
	Contexts       []namedYAMLEntry `yaml:"contexts"`
	Users          []namedYAMLEntry `yaml:"users"`
}

// namedYAMLEntry is a generic { name: <string>, <key>: <node> } entry as
// used in kubeconfig clusters / contexts / users lists. The payload is kept as
// a yaml.Node so we round-trip unknown fields (certificate-authority-data,
// client-key-data, etc.) without loss.
type namedYAMLEntry struct {
	Name    string    `yaml:"name"`
	Cluster yaml.Node `yaml:"cluster,omitempty"`
	Context yaml.Node `yaml:"context,omitempty"`
	User    yaml.Node `yaml:"user,omitempty"`
}

// Merge merges the kubeconfig at srcPath into the kubeconfig at dstPath.
//
// Any cluster, context, or user named contextName already present in dst is
// removed, then the matching entries from src are appended. If setCurrent is
// true the merged file's current-context is set to contextName.
//
// If dstPath does not exist it is created (with mode 0600). The parent
// directory is created if missing.
//
// Merge is intentionally implemented in pure Go and does not shell out to
// kubectl, so it works on machines where kubectl is not installed.
func Merge(srcPath, dstPath, contextName string, setCurrent bool) error {
	src, err := readKubeconfig(srcPath)
	if err != nil {
		return fmt.Errorf("read source kubeconfig %s: %w", srcPath, err)
	}

	dst, err := readKubeconfigOrEmpty(dstPath)
	if err != nil {
		return fmt.Errorf("read destination kubeconfig %s: %w", dstPath, err)
	}

	// Default api headers when creating a fresh file.
	if dst.APIVersion == "" {
		dst.APIVersion = "v1"
	}
	if dst.Kind == "" {
		dst.Kind = "Config"
	}

	dst.Clusters = filterOutNamed(dst.Clusters, contextName)
	dst.Contexts = filterOutNamed(dst.Contexts, contextName)
	dst.Users = filterOutNamed(dst.Users, contextName)

	for _, c := range src.Clusters {
		if c.Name == contextName {
			dst.Clusters = append(dst.Clusters, c)
		}
	}
	for _, c := range src.Contexts {
		if c.Name == contextName {
			dst.Contexts = append(dst.Contexts, c)
		}
	}
	for _, u := range src.Users {
		if u.Name == contextName {
			dst.Users = append(dst.Users, u)
		}
	}

	if setCurrent {
		dst.CurrentContext = contextName
	}

	return writeKubeconfig(dstPath, dst)
}

func filterOutNamed(in []namedYAMLEntry, name string) []namedYAMLEntry {
	out := in[:0:0]
	for _, e := range in {
		if e.Name == name {
			continue
		}
		out = append(out, e)
	}
	return out
}

func readKubeconfig(path string) (*kubeconfigFile, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is supplied by the user via config/flag
	if err != nil {
		return nil, err
	}
	var kc kubeconfigFile
	if err := yaml.Unmarshal(data, &kc); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	return &kc, nil
}

func readKubeconfigOrEmpty(path string) (*kubeconfigFile, error) {
	kc, err := readKubeconfig(path)
	if os.IsNotExist(err) {
		return &kubeconfigFile{}, nil
	}
	return kc, err
}

func writeKubeconfig(path string, kc *kubeconfigFile) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create kubeconfig dir: %w", err)
	}

	out, err := yaml.Marshal(kc)
	if err != nil {
		return fmt.Errorf("marshal yaml: %w", err)
	}

	// Preserve existing mode if the file already exists, otherwise create 0600.
	mode := os.FileMode(0600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}

	// #nosec G306 -- mode is taken from existing file or defaults to 0600
	if err := os.WriteFile(path, out, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
