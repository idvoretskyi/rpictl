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
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Client wraps an SSH connection to a remote host.
type Client struct {
	client *ssh.Client
	host   string
	user   string
}

// Connect establishes an SSH connection using the given key path (or ssh-agent if empty).
func Connect(host, user, keyPath string) (*Client, error) {
	authMethods, err := buildAuthMethods(keyPath)
	if err != nil {
		return nil, fmt.Errorf("build auth: %w", err)
	}

	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // known-host checking is a v0.2.0 feature
		Timeout:         30 * time.Second,
	}

	addr := net.JoinHostPort(host, "22")
	c, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("ssh dial %s: %w", addr, err)
	}

	return &Client{client: c, host: host, user: user}, nil
}

// Close closes the underlying SSH connection.
func (c *Client) Close() error {
	return c.client.Close()
}

// Underlying returns the raw *ssh.Client for use by the SCP package.
func (c *Client) Underlying() *ssh.Client {
	return c.client
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
		conn, err := net.Dial("unix", sock)
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
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, err
	}
	return signer, nil
}
