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

package ssh

import (
	"bytes"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// ExecResult holds the output of a remote command.
type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Exec runs a command on the remote host and returns its output.
// It does NOT return an error for non-zero exit codes — callers check ExitCode.
func (c *Client) Exec(cmd string) (*ExecResult, error) {
	sess, err := c.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	runErr := sess.Run(cmd)

	result := &ExecResult{
		Stdout: strings.TrimRight(stdout.String(), "\n"),
		Stderr: strings.TrimRight(stderr.String(), "\n"),
	}

	if runErr != nil {
		if exitErr, ok := runErr.(*ssh.ExitError); ok {
			result.ExitCode = exitErr.ExitStatus()
			return result, nil
		}
		return nil, fmt.Errorf("run %q: %w", cmd, runErr)
	}

	return result, nil
}

// ExecSudo runs a command with sudo on the remote host.
func (c *Client) ExecSudo(cmd string) (*ExecResult, error) {
	return c.Exec("sudo " + cmd)
}

// MustExec runs a command and returns stdout, returning an error if exit code != 0.
func (c *Client) MustExec(cmd string) (string, error) {
	res, err := c.Exec(cmd)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("command %q exited with code %d: %s", cmd, res.ExitCode, res.Stderr)
	}
	return res.Stdout, nil
}

// MustExecSudo runs a sudo command and returns stdout, returning an error if exit code != 0.
func (c *Client) MustExecSudo(cmd string) (string, error) {
	return c.MustExec("sudo " + cmd)
}
