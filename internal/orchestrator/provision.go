// Copyright 2026 Ihor Dvoretskyi
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

// Package orchestrator coordinates the provision flow: uploading the agent,
// running steps via SSH, parsing JSON results, and rendering progress.
package orchestrator

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/idvoretskyi/rpictl/internal/config"
	"github.com/idvoretskyi/rpictl/internal/kubeconfig"
	internalssh "github.com/idvoretskyi/rpictl/internal/ssh"
)

const remoteAgentPath = "/usr/local/bin/rpictl-agent"

// StepResult mirrors agent.Result for JSON unmarshalling on the laptop side.
type StepResult struct {
	Step       string   `json:"step"`
	OK         bool     `json:"ok"`
	Skipped    bool     `json:"skipped"`
	Changed    []string `json:"changed"`
	DurationMS int64    `json:"duration_ms"`
	Messages   []string `json:"messages"`
}

// Provision runs the full provisioning flow for the given host.
func Provision(hostName string, host *config.Host, agentBinary []byte, force bool) error {
	fmt.Printf("Provisioning host %q (%s@%s)\n\n", hostName, host.User, host.Address)

	// Warn on untested device profiles
	if host.DeviceProfile != "auto" {
		if p, ok := config.GetProfile(host.DeviceProfile); ok && !p.TestedInV01 {
			fmt.Printf("  WARNING: device profile %q has not been physically tested in v0.1.0.\n", host.DeviceProfile)
			fmt.Printf("  Profile defaults are best-effort. Proceeding anyway.\n\n")
		}
	}

	// Connect
	fmt.Printf("  Connecting to %s ...\n", host.Address)
	client, err := internalssh.Connect(host.Address, host.User, host.SSHKey)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer client.Close()
	fmt.Printf("  Connected.\n\n")

	// Upload agent
	if err := uploadAgent(client, agentBinary); err != nil {
		return fmt.Errorf("upload agent: %w", err)
	}

	// Resolve device profile if "auto"
	profile := host.ResolvedProfile()
	if profile == nil {
		// auto: detect from remote
		detectedProfile, err := detectRemoteProfile(client)
		if err != nil {
			fmt.Printf("  WARNING: could not detect device profile: %v; using rpi3 defaults\n", err)
			p, _ := config.GetProfile("rpi3")
			profile = &p
		} else {
			fmt.Printf("  Detected device profile: %s\n\n", detectedProfile)
			p, ok := config.GetProfile(detectedProfile)
			if !ok {
				fmt.Printf("  WARNING: unknown profile %q detected; using rpi3 defaults\n", detectedProfile)
				p, _ = config.GetProfile("rpi3")
			}
			profile = &p
			if !profile.TestedInV01 {
				fmt.Printf("  WARNING: device profile %q has not been physically tested in v0.1.0.\n\n", detectedProfile)
			}
		}
	}

	// Build steps
	steps := buildSteps(hostName, host, profile, force)

	// Run steps
	start := time.Now()
	for _, step := range steps {
		if err := runStep(client, step); err != nil {
			return fmt.Errorf("step %s: %w", step.name, err)
		}
	}

	// Fetch kubeconfig
	fmt.Printf("\n  Fetching kubeconfig ...\n")
	if err := kubeconfig.Fetch(client, host.Address, host.Kubeconfig.Context, host.Kubeconfig.Output); err != nil {
		return fmt.Errorf("kubeconfig: %w", err)
	}
	fmt.Printf("  Kubeconfig written to %s\n", host.Kubeconfig.Output)

	fmt.Printf("\nProvisioning complete in %s.\n\n", time.Since(start).Round(time.Second))
	fmt.Printf("Next steps:\n")
	fmt.Printf("  export KUBECONFIG=%s\n", host.Kubeconfig.Output)
	fmt.Printf("  kubectl get nodes\n\n")
	fmt.Printf("  cd infra/cloudflare && tofu init && tofu apply\n")
	fmt.Printf("  flux bootstrap github --owner=<owner> --repository=<repo> --branch=main --path=clusters/rpi3 --personal\n")

	return nil
}

type step struct {
	name  string
	input map[string]interface{}
}

func buildSteps(hostName string, host *config.Host, profile *config.Profile, force bool) []step {
	zramPct := 0
	swappiness := 0
	gpuMem := 0
	skipGPU := false

	if host.Swap.ZRAMPercent != nil {
		zramPct = *host.Swap.ZRAMPercent
	} else if profile != nil {
		zramPct = profile.ZRAMPercent
	}
	if host.Swap.Swappiness != nil {
		swappiness = *host.Swap.Swappiness
	} else if profile != nil {
		swappiness = profile.Swappiness
	}
	if host.GPUMemMB != nil {
		gpuMem = *host.GPUMemMB
	} else if profile != nil {
		gpuMem = profile.GPUMemMB
		skipGPU = profile.GPUMemMB == 0 // Pi 5: skip entirely
	}

	kubeletArgs := host.K3s.KubeletArgs
	if len(kubeletArgs) == 0 && profile != nil {
		kubeletArgs = []string{"eviction-hard=" + profile.EvictionHard}
	}

	allowSSHFrom := make([]interface{}, len(host.Hardening.UFW.AllowSSHFrom))
	for i, v := range host.Hardening.UFW.AllowSSHFrom {
		allowSSHFrom[i] = v
	}

	disableList := make([]interface{}, len(host.K3s.Disable))
	for i, v := range host.K3s.Disable {
		disableList[i] = v
	}
	kubeletList := make([]interface{}, len(kubeletArgs))
	for i, v := range kubeletArgs {
		kubeletList[i] = v
	}

	passwordAuth := false
	if host.Hardening.SSH.PasswordAuth != nil {
		passwordAuth = *host.Hardening.SSH.PasswordAuth
	}
	permitRoot := false
	if host.Hardening.SSH.PermitRootLogin != nil {
		permitRoot = *host.Hardening.SSH.PermitRootLogin
	}

	return []step{
		{
			name: "preflight",
			input: map[string]interface{}{
				"force": force,
			},
		},
		{
			name: "system",
			input: map[string]interface{}{
				"timezone": host.Timezone,
				"hostname": hostName,
			},
		},
		{
			name: "hardening",
			input: map[string]interface{}{
				"password_auth":       passwordAuth,
				"permit_root_login":   permitRoot,
				"ufw_enabled":         host.Hardening.UFW.Enabled,
				"allow_ssh_from":      allowSSHFrom,
				"unattended_upgrades": host.Hardening.UnattendedUpgrades,
			},
		},
		{
			name: "memory",
			input: map[string]interface{}{
				"zram_percent": zramPct,
				"swappiness":   swappiness,
				"gpu_mem":      gpuMem,
				"skip_gpu_mem": skipGPU,
			},
		},
		{
			name:  "prereqs",
			input: map[string]interface{}{},
		},
		{
			name: "k3s",
			input: map[string]interface{}{
				"version":      host.K3s.Version,
				"disable":      disableList,
				"kubelet_args": kubeletList,
			},
		},
	}
}

func runStep(client *internalssh.Client, s step) error {
	inputJSON, err := json.Marshal(s.input)
	if err != nil {
		return fmt.Errorf("marshal input: %w", err)
	}

	cmd := fmt.Sprintf("sudo %s step %s --input=%q", remoteAgentPath, s.name, string(inputJSON))
	fmt.Printf("  [%-12s] running ...\r", s.name)

	res, err := client.Exec(cmd)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}

	// Parse result from stdout
	var result StepResult
	if parseErr := json.Unmarshal([]byte(res.Stdout), &result); parseErr != nil {
		// Print raw output to help debug
		return fmt.Errorf("parse result (stdout=%q stderr=%q): %w", res.Stdout, res.Stderr, parseErr)
	}

	if !result.OK {
		msg := ""
		if len(result.Messages) > 0 {
			msg = result.Messages[0]
		}
		fmt.Printf("  [%-12s] FAILED  (%dms)\n", s.name, result.DurationMS)
		return fmt.Errorf("%s", msg)
	}

	status := "done"
	if result.Skipped {
		status = "skipped"
	} else if len(result.Changed) > 0 {
		status = "changed"
	}

	fmt.Printf("  [%-12s] %-8s (%dms)", s.name, status, result.DurationMS)
	if len(result.Changed) > 0 {
		fmt.Printf("  changed: %s", strings.Join(result.Changed, ", "))
	}
	fmt.Println()

	return nil
}

func uploadAgent(client *internalssh.Client, agentBinary []byte) error {
	fmt.Printf("  Uploading rpictl-agent ...\r")

	tmpPath := "/tmp/rpictl-agent"
	if err := client.UploadBytes(agentBinary, tmpPath, 0755); err != nil {
		return fmt.Errorf("upload to tmp: %w", err)
	}

	if _, err := client.MustExecSudo(fmt.Sprintf("mv %s %s && chmod 755 %s",
		tmpPath, remoteAgentPath, remoteAgentPath)); err != nil {
		return fmt.Errorf("install agent: %w", err)
	}

	fmt.Printf("  rpictl-agent uploaded to %s\n\n", remoteAgentPath)
	return nil
}

func detectRemoteProfile(client *internalssh.Client) (string, error) {
	model, err := client.MustExec("cat /proc/device-tree/model")
	if err != nil {
		return "", err
	}
	profile := config.DetectProfile(model)
	if profile == "unknown" {
		return "", fmt.Errorf("unrecognized model %q", model)
	}
	return profile, nil
}

// FetchKubeconfig fetches and writes the kubeconfig for an already-provisioned host.
func FetchKubeconfig(hostName string, host *config.Host) error {
	fmt.Printf("Fetching kubeconfig for host %q (%s@%s)\n", hostName, host.User, host.Address)

	client, err := internalssh.Connect(host.Address, host.User, host.SSHKey)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer client.Close()

	if err := kubeconfig.Fetch(client, host.Address, host.Kubeconfig.Context, host.Kubeconfig.Output); err != nil {
		return err
	}

	fmt.Printf("Kubeconfig written to %s\n", host.Kubeconfig.Output)
	fmt.Printf("  kubectl config use-context %s\n", host.Kubeconfig.Context)

	return nil
}

// findConfig looks for rpictl.yaml in the current directory or home directory.
func findConfig(explicit string) string {
	if explicit != "" {
		return explicit
	}
	candidates := []string{
		"rpictl.yaml",
		filepath.Join(mustHomeDir(), ".config", "rpictl", "rpictl.yaml"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return "rpictl.yaml" // fallback; Load will emit a clear error
}

func mustHomeDir() string {
	h, _ := os.UserHomeDir()
	return h
}

// FindConfig is the exported version for CLI use.
func FindConfig(explicit string) string {
	return findConfig(explicit)
}
