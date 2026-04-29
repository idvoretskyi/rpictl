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
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Client wraps an SSH connection to a remote host.
type Client struct {
	client *ssh.Client
	host   string
	user   string
}

// Connect establishes an SSH connection.
//
// keyPath may be empty, in which case ssh-agent (SSH_AUTH_SOCK) is used.
//
// knownHostsFile is the path to a known_hosts file. If the file does not exist
// it is created. When strict is false (default / TOFU mode) an unknown host key
// is automatically appended to the file and the connection is allowed. When
// strict is true any unknown host is rejected with a helpful error message.
// A mismatched host key is always rejected regardless of strict.
func Connect(host, user, keyPath, knownHostsFile string, strict bool) (*Client, error) {
	authMethods, err := buildAuthMethods(keyPath)
	if err != nil {
		return nil, fmt.Errorf("build auth: %w", err)
	}

	hostKeyCB, err := buildHostKeyCallback(host, knownHostsFile, strict)
	if err != nil {
		return nil, fmt.Errorf("build host-key callback: %w", err)
	}

	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCB,
		Timeout:         30 * time.Second,
	}

	addr := net.JoinHostPort(host, "22")
	c, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("ssh dial %s: %w", addr, err)
	}

	return &Client{client: c, host: host, user: user}, nil
}

// buildHostKeyCallback returns an ssh.HostKeyCallback that enforces known-host
// verification with optional Trust-On-First-Use (TOFU) behaviour.
func buildHostKeyCallback(host, knownHostsFile string, strict bool) (ssh.HostKeyCallback, error) {
	// Ensure the known_hosts file exists so knownhosts.New succeeds.
	if err := ensureKnownHostsFile(knownHostsFile); err != nil {
		return nil, err
	}

	baseCallback, err := knownhosts.New(knownHostsFile) // #nosec G304 -- knownHostsFile is a config input under user's control
	if err != nil {
		return nil, fmt.Errorf("load known_hosts %s: %w", knownHostsFile, err)
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := baseCallback(hostname, remote, key)
		if err == nil {
			// Host is known and the key matches — allow.
			return nil
		}

		var keyErr *knownhosts.KeyError
		if !errors.As(err, &keyErr) {
			// Non-key error (e.g. I/O); propagate.
			return err
		}

		if len(keyErr.Want) > 0 {
			// Host IS in known_hosts but with a DIFFERENT key — possible MITM.
			// Never auto-accept a mismatch.
			return fmt.Errorf(
				"SSH host-key mismatch for %s: the host presented a key that differs "+
					"from the one stored in %s.\n"+
					"If the host was reinstalled, remove the old entry with:\n"+
					"  ssh-keygen -R %s -f %s",
				hostname, knownHostsFile, host, knownHostsFile,
			)
		}

		// Host is NOT in known_hosts (keyErr.Want is empty).
		if strict {
			return fmt.Errorf(
				"unknown SSH host %s (strict_host_key is true).\n"+
					"Add it first with:\n"+
					"  ssh-keyscan -H %s >> %s",
				hostname, host, knownHostsFile,
			)
		}

		// TOFU mode: append the key and allow.
		if err := appendKnownHost(knownHostsFile, hostname, remote, key); err != nil {
			return fmt.Errorf("TOFU: append host key for %s: %w", hostname, err)
		}
		return nil
	}, nil
}

// appendKnownHost writes a new known_hosts line for the given host + key.
func appendKnownHost(knownHostsFile, hostname string, remote net.Addr, key ssh.PublicKey) error {
	f, err := os.OpenFile(knownHostsFile, os.O_APPEND|os.O_WRONLY, 0600) // #nosec G304 -- knownHostsFile is a config input under user's control
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key)
	_, err = fmt.Fprintln(f, line)
	return err
}

// ensureKnownHostsFile creates the known_hosts file (and parent dirs) if absent.
func ensureKnownHostsFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil // already exists
	}
	// Create parent directory if needed.
	dir := dirOf(path)
	if dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil { // #nosec G301 -- ~/.ssh convention is 0700
			return fmt.Errorf("create dir %s: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600) // #nosec G304 -- path is config input under user's control
	if err != nil {
		return fmt.Errorf("create known_hosts %s: %w", path, err)
	}
	return f.Close()
}

func buildAuthMethods(keyPath string) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod

	// 1. Explicit key file
	if keyPath != "" {
		signer, err := signerFromKeyFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("load key %s: %w", keyPath, err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
		return methods, nil
	}

	// 2. ssh-agent
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		conn, err := net.Dial("unix", sock) // #nosec G704 -- SSH_AUTH_SOCK is the standard ssh-agent socket env var, not user-controlled at runtime
		if err == nil {
			agentClient := agent.NewClient(conn)
			methods = append(methods, ssh.PublicKeysCallback(agentClient.Signers))
			return methods, nil
		}
	}

	return nil, fmt.Errorf("no SSH key provided and SSH_AUTH_SOCK is not set; " +
		"set ssh_key in rpictl.yaml or start ssh-agent")
}

func signerFromKeyFile(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- key path is a CLI/config input under user's control
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, err
	}
	return signer, nil
}

// Close closes the underlying SSH connection.
func (c *Client) Close() error {
	return c.client.Close()
}

// Underlying returns the raw *ssh.Client for use by the SCP package.
func (c *Client) Underlying() *ssh.Client {
	return c.client
}

func dirOf(path string) string {
	return filepath.Dir(path)
}
