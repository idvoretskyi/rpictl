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

const bootConfig = "/boot/firmware/config.txt"

// RunMemory configures zram swap, swappiness, and gpu_mem on the Pi.
func RunMemory(input StepInput) (*Result, error) {
	result := &Result{OK: true}

	// zram
	zramPct, _ := toInt(input["zram_percent"])
	swappiness, _ := toInt(input["swappiness"])
	gpuMem, _ := toInt(input["gpu_mem"])
	skipGPU, _ := input["skip_gpu_mem"].(bool)

	if zramPct > 0 {
		if _, err := runCommand("apt-get", "install", "-y", "-q", "zram-tools"); err != nil {
			return nil, fmt.Errorf("install zram-tools: %w", err)
		}
		zramConf := fmt.Sprintf("PERCENTAGE=%d\nPRIORITY=100\n", zramPct)
		if err := os.WriteFile("/etc/default/zramswap", []byte(zramConf), 0644); err != nil {
			return nil, fmt.Errorf("write zramswap config: %w", err)
		}
		if _, err := runCommand("systemctl", "restart", "zramswap"); err != nil {
			return nil, fmt.Errorf("restart zramswap: %w", err)
		}
		result.Changed = append(result.Changed, "zram")
		result.Messages = append(result.Messages, fmt.Sprintf("zram enabled at %d%%", zramPct))
	}

	// swappiness
	if swappiness >= 0 {
		val := fmt.Sprintf("vm.swappiness=%d", swappiness)
		if _, err := runCommand("sysctl", "-w", val); err != nil {
			return nil, fmt.Errorf("sysctl %s: %w", val, err)
		}
		confLine := val + "\n"
		if err := appendIfMissing("/etc/sysctl.d/99-rpictl.conf", confLine, "vm.swappiness="); err != nil {
			return nil, fmt.Errorf("persist swappiness: %w", err)
		}
		result.Changed = append(result.Changed, "swappiness")
		result.Messages = append(result.Messages, fmt.Sprintf("vm.swappiness=%d", swappiness))
	}

	// gpu_mem in /boot/firmware/config.txt
	if !skipGPU && gpuMem >= 0 {
		if err := setBootConfigValue("gpu_mem", fmt.Sprintf("%d", gpuMem)); err != nil {
			return nil, fmt.Errorf("set gpu_mem: %w", err)
		}
		result.Changed = append(result.Changed, "gpu_mem")
		result.Messages = append(result.Messages, fmt.Sprintf("gpu_mem=%d", gpuMem))
	}

	return result, nil
}

func toInt(v interface{}) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case float64:
		return int(n), true
	case int64:
		return int(n), true
	}
	return 0, false
}

// appendIfMissing appends line to file if no existing line starts with prefix.
func appendIfMissing(path, line, prefix string) error {
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, l := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(l, prefix) {
			return nil // already set
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = f.WriteString(line)
	return err
}

// setBootConfigValue sets a key=value in /boot/firmware/config.txt,
// replacing any existing line that starts with "key=".
func setBootConfigValue(key, value string) error {
	data, err := os.ReadFile(bootConfig)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	found := false
	newLine := fmt.Sprintf("%s=%s", key, value)
	for i, l := range lines {
		if strings.HasPrefix(l, key+"=") {
			lines[i] = newLine
			found = true
			break
		}
	}
	if !found {
		lines = append(lines, newLine)
	}

	return os.WriteFile(bootConfig, []byte(strings.Join(lines, "\n")), 0644)
}
