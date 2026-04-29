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

// RunPreflight executes the preflight step.
// It checks: aarch64 architecture, Debian Trixie, RAM >= 900MB,
// and detects the device model.
func RunPreflight(input StepInput) (*Result, error) {
	result := &Result{OK: true}

	// Check architecture
	arch, err := readFile("/proc/sys/kernel/ostype")
	if err != nil {
		arch = ""
	}
	uname, err2 := execCmd("uname", "-m")
	if err2 != nil {
		return nil, fmt.Errorf("cannot determine architecture: %w", err2)
	}
	uname = strings.TrimSpace(uname)
	_ = arch
	if uname != "aarch64" {
		return nil, fmt.Errorf("unsupported architecture %q; rpictl requires aarch64", uname)
	}
	result.Messages = append(result.Messages, fmt.Sprintf("architecture: %s", uname))

	// Check Debian Trixie
	osRelease, err := readFile("/etc/os-release")
	if err != nil {
		return nil, fmt.Errorf("read /etc/os-release: %w", err)
	}
	if !strings.Contains(osRelease, `VERSION_CODENAME="trixie"`) &&
		!strings.Contains(osRelease, "VERSION_CODENAME=trixie") {
		force, _ := input["force"].(bool)
		if !force {
			return nil, fmt.Errorf("OS is not Debian Trixie; rpictl requires Trixie " +
				"(pass --force to override at your own risk)")
		}
		result.Messages = append(result.Messages, "WARNING: OS is not Trixie; proceeding due to --force")
	} else {
		result.Messages = append(result.Messages, "OS: Debian Trixie")
	}

	// Check RAM
	memKB, err := readMemTotal()
	if err != nil {
		return nil, fmt.Errorf("check RAM: %w", err)
	}
	memMB := memKB / 1024
	if memMB < 900 {
		return nil, fmt.Errorf("insufficient RAM: %d MB (minimum 900 MB)", memMB)
	}
	result.Messages = append(result.Messages, fmt.Sprintf("RAM: %d MB", memMB))

	// Detect device model
	model, err := readFile("/proc/device-tree/model")
	if err != nil {
		model = "unknown"
	}
	model = strings.TrimRight(model, "\x00\n")
	result.Messages = append(result.Messages, fmt.Sprintf("device: %s", model))

	return result, nil
}

func readFile(path string) (string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- reads system files at known paths
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func execCmd(name string, args ...string) (string, error) {
	// Use os/exec via a thin wrapper so tests can mock it.
	// Real implementation calls exec.Command directly.
	out, err := runCommand(name, args...)
	return out, err
}
