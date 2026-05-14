// Copyright 2026 Ihor Dvoretskyi
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package agent

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// runCommand executes a system command and returns combined stdout.
// Extracted so tests can substitute a mock via build tags if needed.
func runCommand(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output() // #nosec G204 -- agent runs as root on the Pi; commands are constructed by the trusted orchestrator
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// runCommandCombined executes a command and returns combined stdout+stderr.
// Use this when the command writes useful output to stderr (e.g. install scripts).
func runCommandCombined(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput() //nolint:gosec
	return strings.TrimSpace(string(out)), err
}

// runApt runs an apt-get command with DEBIAN_FRONTEND=noninteractive so that
// post-install scripts that try to invoke systemctl or a tty-based frontend
// (e.g. deb-systemd-invoke) do not fail when there is no controlling terminal.
func runApt(args ...string) error {
	cmd := exec.Command("apt-get", args...) //nolint:gosec
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	return cmd.Run()
}

// runCommandStdin executes a command with stdin piped from the given string.
func runCommandStdin(stdin, name string, args ...string) error {
	cmd := exec.Command(name, args...) // #nosec G204 -- agent runs as root on the Pi; commands are constructed by the trusted orchestrator
	cmd.Stdin = strings.NewReader(stdin)
	return cmd.Run()
}

// readMemTotal parses /proc/meminfo and returns MemTotal in kB.
func readMemTotal() (int64, error) {
	data, err := readFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return 0, fmt.Errorf("unexpected MemTotal line: %q", line)
			}
			return strconv.ParseInt(fields[1], 10, 64)
		}
	}
	return 0, fmt.Errorf("MemTotal not found in /proc/meminfo")
}
