// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT
package agent

import (
	"fmt"
)

var prereqPackages = []string{
	"curl",
	"ca-certificates",
	"gnupg",
	"jq",
	"git",
}

// RunPrereqs installs prerequisite packages.
func RunPrereqs(input StepInput) (*Result, error) {
	result := &Result{OK: true}

	if err := runApt("update", "-q"); err != nil {
		return nil, fmt.Errorf("apt-get update: %w", err)
	}

	args := append([]string{"install", "-y", "-q"}, prereqPackages...)
	if err := runApt(args...); err != nil {
		return nil, fmt.Errorf("apt-get install prereqs: %w", err)
	}

	result.Changed = append(result.Changed, "prereqs")
	result.Messages = append(result.Messages, fmt.Sprintf("installed: %v", prereqPackages))

	return result, nil
}
