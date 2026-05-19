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
const cmdlinePath = "/boot/firmware/cmdline.txt"

// RunK3s installs k3s via the official install script.
func RunK3s(input StepInput) (*Result, error) {
	result := &Result{OK: true}

	version, _ := input["version"].(string)
	if version == "" {
		version = "v1.36.0+k3s1"
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

	// Ensure cgroup memory controller is enabled in the kernel cmdline.
	// k3s requires cgroup v2 memory accounting; without this it fails to start
	// on Raspberry Pi OS with "failed to find memory cgroup (v2)".
	cgroupChanged, err := ensureCgroupMemory()
	if err != nil {
		return nil, fmt.Errorf("enable cgroup memory: %w", err)
	}
	if cgroupChanged {
		result.Changed = append(result.Changed, "cgroup-memory")
		result.Messages = append(result.Messages, "cgroup_memory=1 cgroup_enable=memory added to cmdline.txt; reboot required")
		// Return early — k3s install must happen after the reboot.
		// The idempotency marker is NOT written so this step re-runs after reboot.
		result.OK = false
		result.Messages = append(result.Messages, "REBOOT REQUIRED: run 'sudo reboot' on the Pi, then re-run rpictl provision")
		return result, fmt.Errorf("reboot required to activate cgroup memory controller before k3s can start")
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

	// Write installer to a private temp file (random suffix, 0700)
	tmpF, err := os.CreateTemp("", "k3s-install-*.sh")
	if err != nil {
		return nil, fmt.Errorf("create temp installer: %w", err)
	}
	tmpFile := tmpF.Name()
	defer func() { _ = os.Remove(tmpFile) }()
	if err := tmpF.Chmod(0700); err != nil { // #nosec G306 -- executable installer; kept private via random temp path
		_ = tmpF.Close()
		return nil, fmt.Errorf("chmod installer: %w", err)
	}
	if _, err := tmpF.WriteString(installer); err != nil {
		_ = tmpF.Close()
		return nil, fmt.Errorf("write installer: %w", err)
	}
	if err := tmpF.Close(); err != nil {
		return nil, fmt.Errorf("close installer: %w", err)
	}

	// Build INSTALL_K3S_EXEC
	execParts := append(disableFlags, kubeletFlags...)
	execVal := strings.Join(execParts, " ")

	// Set environment and run
	cmd := fmt.Sprintf("INSTALL_K3S_VERSION=%s INSTALL_K3S_EXEC=%q sh %s",
		version, execVal, tmpFile)
	if out, err := runCommandCombined("sh", "-c", cmd); err != nil {
		return nil, fmt.Errorf("k3s install: %w (output: %s)", err, out)
	}

	result.Changed = append(result.Changed, "k3s")
	result.Messages = append(result.Messages, fmt.Sprintf("k3s %s installed", version))

	return result, nil
}

// ensureCgroupMemory adds cgroup_memory=1 and cgroup_enable=memory to
// /boot/firmware/cmdline.txt if not already present.
// Returns true if the file was modified (reboot required).
func ensureCgroupMemory() (bool, error) {
	return ensureCgroupMemoryAt(cmdlinePath)
}

// ensureCgroupMemoryAt is the testable implementation of ensureCgroupMemory.
func ensureCgroupMemoryAt(path string) (bool, error) {
	// #nosec G304 -- path is a fixed system file (cmdline.txt) or a test temp dir, not user-controlled
	data, err := os.ReadFile(path)
	if err != nil {
		// If the file doesn't exist (e.g. on non-RPi hardware), skip silently.
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	// Preserve existing file mode (cmdline.txt is typically 0755 on the boot
	// partition because it lives on a vfat filesystem that maps all files to
	// executable; we keep whatever mode the OS gave it).
	mode := os.FileMode(0o644)
	if info, statErr := os.Stat(path); statErr == nil {
		mode = info.Mode().Perm()
	}

	line := strings.TrimRight(string(data), "\n")
	changed := false

	if !strings.Contains(line, "cgroup_memory=1") {
		line += " cgroup_memory=1"
		changed = true
	}
	if !strings.Contains(line, "cgroup_enable=memory") {
		line += " cgroup_enable=memory"
		changed = true
	}

	if !changed {
		return false, nil
	}

	// #nosec G304 G306 G703 -- path is a fixed system file (cmdline.txt); we preserve the existing mode set by the OS
	if err := os.WriteFile(path, []byte(line+"\n"), mode); err != nil {
		return false, err
	}
	return true, nil
}
