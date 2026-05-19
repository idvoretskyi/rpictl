// Copyright 2026 Ihor Dvoretskyi
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

// captureStdout redirects os.Stdout to a pipe for the duration of fn,
// returning everything written to stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	fn()

	_ = w.Close()
	os.Stdout = orig

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("copy pipe: %v", err)
	}
	return buf.String()
}

// TestEmitErrorWritesToStdout verifies that emitError writes JSON to stdout,
// not stderr. Before the fix, JSON was written to stderr, causing the
// orchestrator's JSON parser to see empty stdout and fail with
// "unexpected end of JSON input".
func TestEmitErrorWritesToStdout(t *testing.T) {
	out := captureStdout(t, func() {
		emitError("teststep", fmt.Errorf("something went wrong"))
	})

	if strings.TrimSpace(out) == "" {
		t.Fatal("emitError produced no stdout; JSON must be written to stdout for the orchestrator to parse it")
	}

	var result Result
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &result); err != nil {
		t.Fatalf("emitError output is not valid JSON: %v\nraw output: %q", err, out)
	}

	if result.OK {
		t.Error("emitError result.OK should be false")
	}
	if result.Step != "teststep" {
		t.Errorf("result.Step = %q, want %q", result.Step, "teststep")
	}
	if len(result.Messages) == 0 || !strings.Contains(result.Messages[0], "something went wrong") {
		t.Errorf("result.Messages = %v, want error message", result.Messages)
	}
}

// TestEmitResultWritesToStdout verifies that successful results also go to stdout.
func TestEmitResultWritesToStdout(t *testing.T) {
	r := &Result{
		Step:    "memory",
		OK:      true,
		Changed: []string{"zram"},
	}

	out := captureStdout(t, func() {
		emitResult(r)
	})

	var got Result
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &got); err != nil {
		t.Fatalf("emitResult output is not valid JSON: %v\nraw: %q", err, out)
	}
	if !got.OK {
		t.Error("got.OK should be true")
	}
	if len(got.Changed) != 1 || got.Changed[0] != "zram" {
		t.Errorf("got.Changed = %v, want [zram]", got.Changed)
	}
}
