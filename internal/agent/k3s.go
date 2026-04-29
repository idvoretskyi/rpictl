// Copyright 2026 Ihor Dvoretskyi
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package agent

import (
	"fmt"
	"os"
	"strings"
)

const k3sInstallerURL = "https://get.k3s.io"

// RunK3s installs k3s via the official install script.
func RunK3s(input StepInput) (*Result, error) {
	result := &Result{OK: true}

	version, _ := input["version"].(string)
	if version == "" {
		version = "v1.31.4+k3s1"
	}

	disableRaw, _ := input["disable"].([]interface{})
	var disableFlags []string
	for _, d := range disableRaw {
		if s, ok := d.(string); ok {
			disableFlags = append(disableFlags, "--disable="+s)
		}
	}

	kubeletArgsRaw, _ := input["kubelet_args"].([]interface{})
	var kubeletFlags []string
	for _, a := range kubeletArgsRaw {
		if s, ok := a.(string); ok {
			kubeletFlags = append(kubeletFlags, "--kubelet-arg="+s)
		}
	}

	// Check if already installed at correct version
	if out, err := runCommand("k3s", "--version"); err == nil {
		if strings.Contains(out, version) {
			result.Messages = append(result.Messages, fmt.Sprintf("k3s %s already installed", version))
			return result, nil
		}
	}

	// Download installer
	installer, err := runCommand("curl", "-sfL", k3sInstallerURL)
	if err != nil {
		return nil, fmt.Errorf("download k3s installer: %w", err)
	}

	// Write installer to temp file
	tmpFile := "/tmp/k3s-install.sh"
	if err := os.WriteFile(tmpFile, []byte(installer), 0755); err != nil {
		return nil, fmt.Errorf("write installer: %w", err)
	}
	defer func() { _ = os.Remove(tmpFile) }()

	// Build INSTALL_K3S_EXEC
	execParts := append(disableFlags, kubeletFlags...)
	execVal := strings.Join(execParts, " ")

	// Set environment and run
	cmd := fmt.Sprintf("INSTALL_K3S_VERSION=%s INSTALL_K3S_EXEC=%q sh %s",
		version, execVal, tmpFile)
	if out, err := runCommand("sh", "-c", cmd); err != nil {
		return nil, fmt.Errorf("k3s install: %w (output: %s)", err, out)
	}

	result.Changed = append(result.Changed, "k3s")
	result.Messages = append(result.Messages, fmt.Sprintf("k3s %s installed", version))

	return result, nil
}
