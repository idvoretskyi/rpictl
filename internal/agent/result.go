// Copyright 2026 Ihor Dvoretskyi
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package agent implements the rpictl-agent step execution logic.
// Each step is idempotent: it writes a marker to /var/lib/rpictl/<step>.done
// containing a SHA256 hash of its input JSON. On re-run, if the hash matches,
// the step is skipped.
package agent

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const markerDir = "/var/lib/rpictl"

// Result is the JSON contract emitted to stdout by each agent step.
type Result struct {
	Step       string   `json:"step"`
	OK         bool     `json:"ok"`
	Skipped    bool     `json:"skipped"`
	Changed    []string `json:"changed"`
	DurationMS int64    `json:"duration_ms"`
	Messages   []string `json:"messages"`
}

// StepInput is the JSON passed to each agent step via --input flag.
type StepInput map[string]interface{}

// Runner executes a named step function and emits a Result to stdout.
func Runner(stepName string, inputJSON string, fn func(input StepInput) (*Result, error)) {
	start := time.Now()

	var input StepInput
	if err := json.Unmarshal([]byte(inputJSON), &input); err != nil {
		emitError(stepName, fmt.Errorf("parse input: %w", err))
		os.Exit(1)
	}

	// Idempotency check
	hash := inputHash(inputJSON)
	if checkMarker(stepName, hash) {
		result := &Result{
			Step:       stepName,
			OK:         true,
			Skipped:    true,
			DurationMS: time.Since(start).Milliseconds(),
			Messages:   []string{"step already completed with same input; skipping"},
		}
		emitResult(result)
		return
	}

	result, err := fn(input)
	if err != nil {
		// If the step populated a structured result before returning the error,
		// emit it so the orchestrator sees Messages/Changed (e.g. reboot guidance
		// from RunK3s when cgroup_memory was just enabled). The marker is
		// intentionally NOT written so the step re-runs.
		if result != nil {
			result.Step = stepName
			result.OK = false
			result.DurationMS = time.Since(start).Milliseconds()
			if len(result.Messages) == 0 {
				result.Messages = []string{err.Error()}
			}
			emitResult(result)
		} else {
			emitError(stepName, err)
		}
		os.Exit(1)
	}

	result.Step = stepName
	result.DurationMS = time.Since(start).Milliseconds()
	if result.OK {
		writeMarker(stepName, hash)
	}

	emitResult(result)
}

func emitResult(r *Result) {
	data, _ := json.Marshal(r)
	fmt.Println(string(data))
}

func emitError(step string, err error) {
	r := &Result{
		Step:     step,
		OK:       false,
		Messages: []string{err.Error()},
	}
	data, _ := json.Marshal(r)
	fmt.Println(string(data))
}

func inputHash(input string) string {
	h := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", h)
}

func markerPath(step string) string {
	return filepath.Join(markerDir, step+".done")
}

func checkMarker(step, hash string) bool {
	data, err := os.ReadFile(markerPath(step))
	if err != nil {
		return false
	}
	return string(data) == hash
}

func writeMarker(step, hash string) {
	if err := os.MkdirAll(markerDir, 0750); err != nil { // tightened: local state dir, no need for world-execute
		return
	}
	_ = os.WriteFile(markerPath(step), []byte(hash), 0600) // tightened: marker file contains a hash, no reason for world-read
}
