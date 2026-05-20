// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT
package agent

import (
	"fmt"
	"os"
)

const (
	k3sConfigPath      = "/etc/rancher/k3s/config.yaml"
	k3sAuditPolicyPath = "/etc/rancher/k3s/audit.yaml"
	k3sLogrotatePath   = "/etc/logrotate.d/k3s-audit"
)

const k3sAuditPolicy = `# Managed by rpictl — do not edit manually
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: Metadata
    resources:
    - group: ""
      resources: ["secrets", "configmaps"]
  - level: RequestResponse
    users: ["system:admin"]
  - level: None
    userGroups: ["system:authenticated"]
    nonResourceURLs:
    - "/api*"
    - "/version"
  - level: Metadata
`

const k3sLogrotateContent = `# Managed by rpictl
/var/log/k3s-audit.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}
`

// applyK3sCIS applies Layer 11 — k3s CIS benchmark (strict only).
// Configuration is delivered via /etc/rancher/k3s/config.yaml which k3s
// reads natively on startup. We do NOT modify the systemd unit.
func applyK3sCIS(input StepInput) ([]string, []string, error) {
	enabled := boolVal(boolPtr(input, "cis_benchmark"), false)
	if !enabled {
		return nil, nil, nil
	}

	hash := inputHash(fmt.Sprintf("%v", input["cis_benchmark"]))
	if hardeningMarkerExists("k3s-cis", hash) {
		return nil, []string{"k3s-cis: already applied"}, nil
	}

	// Write audit policy
	if err := os.MkdirAll("/etc/rancher/k3s", 0750); err != nil {
		return nil, nil, fmt.Errorf("mkdir /etc/rancher/k3s: %w", err)
	}
	if err := backupFile(k3sAuditPolicyPath); err != nil {
		return nil, nil, fmt.Errorf("backup k3s audit policy: %w", err)
	}
	safeAudit, err := validateHardeningPath(k3sAuditPolicyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("validate k3s audit policy path: %w", err)
	}
	if err := os.WriteFile(safeAudit, []byte(k3sAuditPolicy), 0640); err != nil { // #nosec G306 G703 -- audit policy: 0640 is standard; path validated by allowlist
		return nil, nil, fmt.Errorf("write k3s audit policy: %w", err)
	}

	// Merge CIS flags into k3s config.yaml
	if err := mergeK3sConfig(); err != nil {
		return nil, nil, fmt.Errorf("merge k3s config: %w", err)
	}

	// Logrotate for audit log
	if safeLogrotate, err := validateHardeningPath(k3sLogrotatePath); err == nil {
		if err := os.WriteFile(safeLogrotate, []byte(k3sLogrotateContent), 0644); err != nil { // #nosec G306 -- logrotate configs must be world-readable
			// Non-fatal
			_ = err
		}
	}

	// Restart k3s to pick up new config
	if _, err := runCommand("systemctl", "restart", "k3s"); err != nil {
		return nil, nil, fmt.Errorf("restart k3s after CIS config: %w", err)
	}

	writeHardeningMarker("k3s-cis", hash)
	return []string{"k3s-cis"}, []string{"k3s CIS benchmark: audit logging + protect-kernel-defaults + read-only kubelet port"}, nil
}

// mergeK3sConfig merges CIS hardening flags into /etc/rancher/k3s/config.yaml.
// Existing user config is preserved; we add missing keys only.
func mergeK3sConfig() error {
	if err := backupFile(k3sConfigPath); err != nil {
		return fmt.Errorf("backup k3s config: %w", err)
	}

	// CIS flags we inject
	cisConfig := map[string]interface{}{
		"protect-kernel-defaults": true,
		"kube-apiserver-arg": []string{
			"audit-log-path=/var/log/k3s-audit.log",
			"audit-log-maxage=30",
			"audit-log-maxbackup=10",
			"audit-policy-file=" + k3sAuditPolicyPath,
			"request-timeout=300s",
		},
		"kubelet-arg": []string{
			"streaming-connection-idle-timeout=5m",
			"protect-kernel-defaults=true",
			"read-only-port=0",
			"event-qps=0",
		},
	}

	// Read existing config if present
	existing := map[string]interface{}{}
	if safeK3s, err := validateHardeningPath(k3sConfigPath); err == nil {
		if data, err := os.ReadFile(safeK3s); err == nil { // #nosec G304 -- path validated by validateHardeningPath allowlist
			// Parse as simple YAML key:value — use our minimal parser
			existing = parseSimpleYAML(string(data))
		}
	}

	// Merge: only add keys not already present
	for k, v := range cisConfig {
		if _, exists := existing[k]; !exists {
			existing[k] = v
		}
	}

	// Write merged config
	content := marshalSimpleYAML(existing)
	safeK3s, err := validateHardeningPath(k3sConfigPath)
	if err != nil {
		return fmt.Errorf("validate k3s config path: %w", err)
	}
	if err := os.WriteFile(safeK3s, []byte(content), 0640); err != nil { // #nosec G306 G703 -- k3s config.yaml: 0640 is standard (k3s reads as root); path validated by allowlist
		return fmt.Errorf("write k3s config: %w", err)
	}
	return nil
}

// unhardenK3sCIS removes CIS hardening from k3s config.
func unhardenK3sCIS() error {
	_ = restoreFile(k3sConfigPath)
	_ = restoreFile(k3sAuditPolicyPath)
	_ = os.Remove(k3sLogrotatePath)
	_, _ = runCommand("systemctl", "restart", "k3s")
	removeHardeningMarker("k3s-cis")
	return nil
}
