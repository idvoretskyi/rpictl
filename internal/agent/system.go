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

// RunSystem executes the system step: apt upgrade + timezone + hostname.
func RunSystem(input StepInput) (*Result, error) {
	result := &Result{OK: true}

	// apt-get update + upgrade
	if err := runApt("update", "-q"); err != nil {
		return nil, fmt.Errorf("apt-get update: %w", err)
	}
	if err := runApt("upgrade", "-y", "-q"); err != nil {
		return nil, fmt.Errorf("apt-get upgrade: %w", err)
	}
	result.Changed = append(result.Changed, "apt-upgrade")
	result.Messages = append(result.Messages, "packages upgraded")

	// Set timezone
	tz, _ := input["timezone"].(string)
	if tz == "" {
		tz = "UTC"
	}
	if _, err := runCommand("timedatectl", "set-timezone", tz); err != nil {
		return nil, fmt.Errorf("set timezone %s: %w", tz, err)
	}
	result.Changed = append(result.Changed, "timezone")
	result.Messages = append(result.Messages, fmt.Sprintf("timezone set to %s", tz))

	// Set hostname
	hostname, _ := input["hostname"].(string)
	if hostname != "" {
		current, _ := runCommand("hostname")
		if strings.TrimSpace(current) != hostname {
			if _, err := runCommand("hostnamectl", "set-hostname", hostname); err != nil {
				return nil, fmt.Errorf("set hostname %s: %w", hostname, err)
			}
			// Update /etc/hosts so sudo can resolve the new hostname without warnings.
			if err := updateHostsFile(hostname); err != nil {
				return nil, fmt.Errorf("update /etc/hosts: %w", err)
			}
			result.Changed = append(result.Changed, "hostname")
			result.Messages = append(result.Messages, fmt.Sprintf("hostname set to %s", hostname))
		}
	}

	return result, nil
}

// updateHostsFile ensures 127.0.1.1 maps to the given hostname in /etc/hosts.
func updateHostsFile(hostname string) error {
	return updateHostsFileAt("/etc/hosts", hostname)
}

// updateHostsFileAt is the testable implementation of updateHostsFile.
// It replaces any existing 127.0.1.1 line (or appends one) so that sudo can
// resolve the hostname without printing "unable to resolve host" warnings.
func updateHostsFileAt(path, hostname string) error {
	// #nosec G304 -- path is a fixed system file (/etc/hosts) or a test temp dir, not user-controlled
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// Preserve existing file mode (typically 0644 for /etc/hosts, world-readable
	// is required for non-root processes to resolve hostnames).
	mode := os.FileMode(0o644)
	if info, statErr := os.Stat(path); statErr == nil {
		mode = info.Mode().Perm()
	}
	lines := strings.Split(string(data), "\n")
	found := false
	newLine := fmt.Sprintf("127.0.1.1\t%s", hostname)
	for i, l := range lines {
		// Match the first whitespace-separated field exactly so we don't
		// accidentally replace 127.0.1.10 or a commented line that happens to
		// start with 127.0.1.1 in a longer token.
		trimmed := strings.TrimLeft(l, " \t")
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) > 0 && fields[0] == "127.0.1.1" {
			lines[i] = newLine
			found = true
			break
		}
	}
	if !found {
		lines = append(lines, newLine)
	}
	// #nosec G304 G306 G703 -- path is a fixed system file (/etc/hosts); world-readable perms are required for hostname resolution by non-root processes
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), mode)
}
