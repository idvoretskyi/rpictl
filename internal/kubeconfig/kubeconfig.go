// Copyright 2026 Ihor Dvoretskyi
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

// Package kubeconfig fetches and rewrites the k3s kubeconfig from a remote host.
package kubeconfig

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	internalssh "github.com/idvoretskyi/rpictl/internal/ssh"
)

const remoteKubeconfigPath = "/etc/rancher/k3s/k3s.yaml"

// k3sReadyTimeout is how long to wait for k3s to write its kubeconfig after install.
const k3sReadyTimeout = 2 * time.Minute

// Fetch retrieves the k3s kubeconfig from the remote host, rewrites the server
// address to use the host's address, renames the context, and writes it to outputPath.
func Fetch(client *internalssh.Client, hostAddress, contextName, outputPath string) error {
	raw, err := waitForKubeconfig(client)
	if err != nil {
		return fmt.Errorf("read remote kubeconfig: %w", err)
	}

	rewritten, err := rewrite(raw, hostAddress, contextName)
	if err != nil {
		return fmt.Errorf("rewrite kubeconfig: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0700); err != nil {
		return fmt.Errorf("create kubeconfig dir: %w", err)
	}

	if err := os.WriteFile(outputPath, []byte(rewritten), 0600); err != nil {
		return fmt.Errorf("write kubeconfig to %s: %w", outputPath, err)
	}

	return nil
}

// waitForKubeconfig polls until k3s writes its kubeconfig (it takes a few seconds
// to start after installation) or until k3sReadyTimeout is reached.
func waitForKubeconfig(client *internalssh.Client) (string, error) {
	deadline := time.Now().Add(k3sReadyTimeout)
	for time.Now().Before(deadline) {
		raw, err := client.MustExecSudo("cat " + remoteKubeconfigPath)
		if err == nil && strings.TrimSpace(raw) != "" {
			return raw, nil
		}
		time.Sleep(5 * time.Second)
	}
	return "", fmt.Errorf("k3s kubeconfig not available after %s; k3s may still be starting", k3sReadyTimeout)
}

// rewrite replaces the server address (127.0.0.1 or localhost) with the actual
// host address, and renames the cluster/context/user to contextName.
// hostAddress should be an IP address so that TLS SAN validation passes
// (k3s includes the node IP in its cert SANs but not mDNS .local names).
// IPv6 literals are automatically bracketed via net.JoinHostPort.
func rewrite(raw, hostAddress, contextName string) (string, error) {
	// net.JoinHostPort wraps IPv6 literals in [] but leaves IPv4 / hostnames
	// untouched, producing a valid URL authority in both cases.
	serverAuthority := net.JoinHostPort(hostAddress, "6443")
	serverURL := fmt.Sprintf("https://%s", serverAuthority)

	out := raw

	// Replace server address
	out = strings.ReplaceAll(out, "https://127.0.0.1:6443", serverURL)
	out = strings.ReplaceAll(out, "https://localhost:6443", serverURL)

	// Rename default cluster/context/user names
	out = strings.ReplaceAll(out, "name: default", fmt.Sprintf("name: %s", contextName))
	out = strings.ReplaceAll(out, "cluster: default", fmt.Sprintf("cluster: %s", contextName))
	out = strings.ReplaceAll(out, "user: default", fmt.Sprintf("user: %s", contextName))
	out = strings.ReplaceAll(out, "current-context: default", fmt.Sprintf("current-context: %s", contextName))

	return out, nil
}
