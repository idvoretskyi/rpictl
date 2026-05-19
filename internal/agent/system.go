// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT
package agent

import (
	"fmt"
	"strings"
)

// RunSystem executes the system step: apt upgrade + timezone + hostname.
func RunSystem(input StepInput) (*Result, error) {
	result := &Result{OK: true}

	// apt-get update + upgrade
	if _, err := runCommand("apt-get", "update", "-q"); err != nil {
		return nil, fmt.Errorf("apt-get update: %w", err)
	}
	if _, err := runCommand("apt-get", "upgrade", "-y", "-q"); err != nil {
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
			result.Changed = append(result.Changed, "hostname")
			result.Messages = append(result.Messages, fmt.Sprintf("hostname set to %s", hostname))
		}
	}

	return result, nil
}
