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

	if _, err := runCommand("apt-get", "update", "-q"); err != nil {
		return nil, fmt.Errorf("apt-get update: %w", err)
	}

	args := append([]string{"install", "-y", "-q"}, prereqPackages...)
	if _, err := runCommand("apt-get", args...); err != nil {
		return nil, fmt.Errorf("apt-get install prereqs: %w", err)
	}

	result.Changed = append(result.Changed, "prereqs")
	result.Messages = append(result.Messages, fmt.Sprintf("installed: %v", prereqPackages))

	return result, nil
}
