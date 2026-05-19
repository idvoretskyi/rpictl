// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT
// Package kubeconfig fetches and rewrites the k3s kubeconfig from a remote host.
package kubeconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	internalssh "github.com/idvoretskyi/rpictl/internal/ssh"
)

const remoteKubeconfigPath = "/etc/rancher/k3s/k3s.yaml"

// Fetch retrieves the k3s kubeconfig from the remote host, rewrites the server
// address to use the host's address, renames the context, and writes it to outputPath.
func Fetch(client *internalssh.Client, hostAddress, contextName, outputPath string) error {
	raw, err := client.MustExecSudo("cat " + remoteKubeconfigPath)
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

// rewrite replaces the server address (127.0.0.1 or localhost) with the actual
// host address, and renames the cluster/context/user to contextName.
func rewrite(raw, hostAddress, contextName string) (string, error) {
	out := raw

	// Replace server address
	out = strings.ReplaceAll(out, "https://127.0.0.1:6443", fmt.Sprintf("https://%s:6443", hostAddress))
	out = strings.ReplaceAll(out, "https://localhost:6443", fmt.Sprintf("https://%s:6443", hostAddress))

	// Rename default cluster/context/user names
	out = strings.ReplaceAll(out, "name: default", fmt.Sprintf("name: %s", contextName))
	out = strings.ReplaceAll(out, "cluster: default", fmt.Sprintf("cluster: %s", contextName))
	out = strings.ReplaceAll(out, "user: default", fmt.Sprintf("user: %s", contextName))
	out = strings.ReplaceAll(out, "current-context: default", fmt.Sprintf("current-context: %s", contextName))

	return out, nil
}
