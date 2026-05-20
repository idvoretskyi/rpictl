// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT
// Package orchestrator coordinates the provision flow: uploading the agent,
// running steps via SSH, parsing JSON results, and rendering progress.
package orchestrator

import (
	"encoding/json"
	"fmt"
	"net"
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

	// Warn on untested hardening profiles for Pi 4/5
	if host.DeviceProfile == "rpi4" || host.DeviceProfile == "rpi5" {
		lvl := string(host.Hardening.Level)
		if lvl == "standard" || lvl == "strict" {
			fmt.Printf("  WARNING: hardening level %q on %q has not been hardware-validated.\n", lvl, host.DeviceProfile)
			fmt.Printf("  Please report results at https://github.com/idvoretskyi/rpictl/issues\n\n")
		}
	}

	// Connect
	fmt.Printf("  Connecting to %s ...\n", host.Address)
	client, err := internalssh.Connect(host.Address, host.User, host.SSHKey, host.KnownHostsFile, *host.StrictHostKey)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = client.Close() }()
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

	// Run pre-hardening steps
	start := time.Now()
	for _, s := range steps {
		if err := runStep(client, s); err != nil {
			return fmt.Errorf("step %s: %w", s.name, err)
		}
		// After hardening step: perform SSH liveness check + auto-rollback if needed
		if s.name == "hardening" && host.Hardening.Level != "off" {
			if err := sshLivenessCheck(host, client); err != nil {
				return err
			}
		}
	}

	// harden-verify
	if host.Hardening.Level != "off" {
		reportPath, err := runHardenVerify(client, host)
		if err != nil {
			// Non-fatal: log and continue
			fmt.Printf("  [harden-verify] WARNING: %v\n", err)
		} else if reportPath != "" {
			fmt.Printf("  [harden-verify] report written to %s\n", reportPath)
		}
	}

	// Fetch kubeconfig — resolve hostname to IP so TLS SAN validation passes
	// (k3s includes the node IP in its cert but not mDNS .local hostnames).
	fmt.Printf("\n  Fetching kubeconfig ...\n")
	kubeconfigAddr := resolveToIP(host.Address)
	if err := kubeconfig.Fetch(client, kubeconfigAddr, host.Kubeconfig.Context, host.Kubeconfig.Output); err != nil {
		return fmt.Errorf("kubeconfig: %w", err)
	}
	fmt.Printf("  Kubeconfig written to %s\n", host.Kubeconfig.Output)

	if err := mergeKubeconfig(host); err != nil {
		return fmt.Errorf("kubeconfig merge: %w", err)
	}

	fmt.Printf("\nProvisioning complete in %s.\n\n", time.Since(start).Round(time.Second))
	fmt.Printf("Next steps:\n")
	if host.Kubeconfig.Merge != nil && *host.Kubeconfig.Merge {
		if host.Kubeconfig.SetCurrent != nil && *host.Kubeconfig.SetCurrent {
			fmt.Printf("  kubectl get nodes    # context %q is already active\n\n", host.Kubeconfig.Context)
		} else {
			fmt.Printf("  kubectl --context=%s get nodes\n", host.Kubeconfig.Context)
			fmt.Printf("  kubectl config use-context %s    # make it the default\n\n", host.Kubeconfig.Context)
		}
	} else {
		fmt.Printf("  export KUBECONFIG=%s\n", host.Kubeconfig.Output)
		fmt.Printf("  kubectl get nodes\n\n")
	}
	fmt.Printf("  cd infra/cloudflare && tofu init && tofu apply\n")
	fmt.Printf("  flux bootstrap github --owner=<owner> --repository=<repo> --branch=main --path=clusters/rpi3 --personal\n")

	return nil
}

// sshLivenessCheck opens a NEW SSH connection to the host to verify SSH is
// still reachable after hardening. On failure, it sends a rollback command
// over the original (still-open) client connection and returns an error.
// This protects against accidental SSH lockout.
func sshLivenessCheck(host *config.Host, originalClient *internalssh.Client) error {
	fmt.Printf("  [ssh-liveness ] checking SSH reachability post-hardening ...\r")

	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		testClient, err := internalssh.Connect(
			host.Address, host.User, host.SSHKey, host.KnownHostsFile, *host.StrictHostKey,
		)
		if err == nil {
			_ = testClient.Close()
			fmt.Printf("  [ssh-liveness ] ok                                              \n")
			return nil
		}
		lastErr = err
		time.Sleep(2 * time.Second)
	}

	// Liveness check failed — attempt rollback over original connection
	fmt.Printf("\n  *** SSH liveness check FAILED after hardening: %v\n", lastErr)
	fmt.Printf("  *** Attempting automatic SSH rollback ...\n")

	rollbackCmd := fmt.Sprintf("sudo %s step unharden --input=%q",
		remoteAgentPath, `{"layers":["ssh"]}`)
	_, rollbackErr := originalClient.Exec(rollbackCmd)
	if rollbackErr != nil {
		// Dual failure — emit recovery instructions
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "*** HARDENING ROLLBACK FAILED — DEVICE MAY BE UNREACHABLE ***\n")
		fmt.Fprintf(os.Stderr, "SSH liveness check failed: %v\n", lastErr)
		fmt.Fprintf(os.Stderr, "Rollback attempt failed: %v\n", rollbackErr)
		fmt.Fprintf(os.Stderr, "\nManual recovery steps:\n")
		fmt.Fprintf(os.Stderr, "  1. Connect a keyboard + monitor to the Pi, or mount the SD card on another machine\n")
		fmt.Fprintf(os.Stderr, "  2. Restore: for f in $(find /etc -name '*.bak.rpictl' 2>/dev/null); do cp \"$f\" \"${f%%.bak.rpictl}\"; done\n")
		fmt.Fprintf(os.Stderr, "  3. Remove rpictl sshd config: rm -f /etc/ssh/sshd_config.d/rpictl-hardening.conf\n")
		fmt.Fprintf(os.Stderr, "  4. Run: systemctl reload ssh\n")
		fmt.Fprintf(os.Stderr, "  5. Or simply reboot: the original sshd config will be restored\n")
		writeRecoveryJSON(host.Address, lastErr, rollbackErr)
		return fmt.Errorf("SSH lockout: liveness check failed (%v) AND rollback failed (%v); see recovery instructions above", lastErr, rollbackErr)
	}

	fmt.Printf("  *** SSH rollback succeeded — SSH hardening has been reverted\n")
	return fmt.Errorf("SSH liveness check failed after hardening (%v); SSH hardening was automatically rolled back. "+
		"Review your hardening.ssh config (allowed_users, port, cipher restrictions) and re-run provision", lastErr)
}

// writeRecoveryJSON writes a recovery info file to the user's data dir.
func writeRecoveryJSON(host string, livenessErr, rollbackErr error) {
	dir := hardeningReportDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return
	}
	ts := time.Now().UTC().Format("2006-01-02T15-04-05")
	path := filepath.Join(dir, fmt.Sprintf("%s-recovery-%s.json", sanitizeFilename(host), ts))
	content := fmt.Sprintf(`{"host":%q,"timestamp":%q,"liveness_error":%q,"rollback_error":%q,"recovery_steps":["connect keyboard+monitor","restore .bak.rpictl files","rm /etc/ssh/sshd_config.d/rpictl-hardening.conf","systemctl reload ssh"]}`,
		host, ts, livenessErr.Error(), rollbackErr.Error())
	_ = os.WriteFile(path, []byte(content), 0600)
	fmt.Fprintf(os.Stderr, "  Recovery info written to %s\n", path)
}

// runHardenVerify runs the harden-verify agent step and writes the JSON report.
func runHardenVerify(client *internalssh.Client, host *config.Host) (string, error) {
	level := string(host.Hardening.Level)
	disableBT := false
	if host.Hardening.Services.DisableBluetooth != nil {
		disableBT = *host.Hardening.Services.DisableBluetooth
	}

	input := map[string]interface{}{
		"level":             level,
		"disable_bluetooth": disableBT,
	}
	s := step{name: "harden-verify", input: input}

	fmt.Printf("  [harden-verify] running ...\r")
	if err := runStep(client, s); err != nil {
		return "", err
	}

	// Re-run to get the raw result for the report
	inputJSON, _ := json.Marshal(input)
	cmd := fmt.Sprintf("sudo %s step harden-verify --input=%q", remoteAgentPath, string(inputJSON))
	res, err := client.Exec(cmd)
	if err != nil {
		return "", nil // already logged by runStep above, skip report
	}

	var result StepResult
	if err := json.Unmarshal([]byte(res.Stdout), &result); err != nil {
		return "", nil
	}

	// Write report
	if len(result.Messages) > 0 {
		return writeHardeningReport(host.Address, result.Messages[0])
	}
	return "", nil
}

// writeHardeningReport writes the JSON verification report to the local disk.
func writeHardeningReport(host, reportJSON string) (string, error) {
	dir := hardeningReportDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("mkdir report dir: %w", err)
	}
	ts := time.Now().UTC().Format("2006-01-02T15-04-05")
	path := filepath.Join(dir, fmt.Sprintf("%s-hardening-%s.json", sanitizeFilename(host), ts))
	if err := os.WriteFile(path, []byte(reportJSON), 0600); err != nil {
		return "", fmt.Errorf("write report: %w", err)
	}
	return path, nil
}

// hardeningReportDir returns the XDG data home path for rpictl reports.
func hardeningReportDir() string {
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return filepath.Join(xdg, "rpictl")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "rpictl")
}

// sanitizeFilename replaces characters not safe for filenames.
func sanitizeFilename(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|' {
			b.WriteRune('_')
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// Unharden connects to a host and reverses applied hardening layers.
func Unharden(hostName string, host *config.Host, agentBinary []byte, layers []string) error {
	fmt.Printf("Unhardening host %q (%s@%s)\n\n", hostName, host.User, host.Address)

	client, err := internalssh.Connect(host.Address, host.User, host.SSHKey, host.KnownHostsFile, *host.StrictHostKey)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = client.Close() }()

	// Ensure agent is current
	if err := uploadAgent(client, agentBinary); err != nil {
		return fmt.Errorf("upload agent: %w", err)
	}

	layerList := make([]interface{}, len(layers))
	for i, l := range layers {
		layerList[i] = l
	}
	s := step{
		name:  "unharden",
		input: map[string]interface{}{"layers": layerList},
	}
	if err := runStep(client, s); err != nil {
		return fmt.Errorf("unharden: %w", err)
	}

	// SSH liveness check post-unharden
	fmt.Printf("  Verifying SSH still reachable ...\n")
	testClient, err := internalssh.Connect(host.Address, host.User, host.SSHKey, host.KnownHostsFile, *host.StrictHostKey)
	if err != nil {
		return fmt.Errorf("unharden completed but SSH liveness check failed: %w", err)
	}
	_ = testClient.Close()

	fmt.Printf("  SSH liveness check passed.\n")
	fmt.Printf("\nUnharden complete.\n")
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

	disableList := make([]interface{}, len(host.K3s.Disable))
	for i, v := range host.K3s.Disable {
		disableList[i] = v
	}
	kubeletList := make([]interface{}, len(kubeletArgs))
	for i, v := range kubeletArgs {
		kubeletList[i] = v
	}

	allowSSHFrom := make([]interface{}, len(host.Hardening.Firewall.AllowSSHFrom))
	for i, v := range host.Hardening.Firewall.AllowSSHFrom {
		allowSSHFrom[i] = v
	}

	allowUsers := make([]interface{}, len(host.Hardening.SSH.AllowUsers))
	for i, v := range host.Hardening.SSH.AllowUsers {
		allowUsers[i] = v
	}

	passwordAuth := false
	if host.Hardening.SSH.PasswordAuth != nil {
		passwordAuth = *host.Hardening.SSH.PasswordAuth
	}
	permitRoot := false
	if host.Hardening.SSH.PermitRootLogin != nil {
		permitRoot = *host.Hardening.SSH.PermitRootLogin
	}
	maxAuthTries := 3
	if host.Hardening.SSH.MaxAuthTries != nil {
		maxAuthTries = *host.Hardening.SSH.MaxAuthTries
	}
	ufwEnabled := false
	if host.Hardening.Firewall.Enabled != nil {
		ufwEnabled = *host.Hardening.Firewall.Enabled
	}
	rateLimitSSH := false
	if host.Hardening.Firewall.RateLimitSSH != nil {
		rateLimitSSH = *host.Hardening.Firewall.RateLimitSSH
	}
	allowK3sPorts := false
	if host.Hardening.Firewall.AllowK3sPorts != nil {
		allowK3sPorts = *host.Hardening.Firewall.AllowK3sPorts
	}
	unattendedUpgrades := false
	if host.Hardening.UnattendedUpgrades != nil {
		unattendedUpgrades = *host.Hardening.UnattendedUpgrades
	}
	sysctlHardening := false
	if host.Hardening.Kernel.SysctlHardening != nil {
		sysctlHardening = *host.Hardening.Kernel.SysctlHardening
	}
	fail2ban := false
	if host.Hardening.Audit.Fail2ban != nil {
		fail2ban = *host.Hardening.Audit.Fail2ban
	}
	auditd := false
	if host.Hardening.Audit.Auditd != nil {
		auditd = *host.Hardening.Audit.Auditd
	}
	disableBT := false
	if host.Hardening.Services.DisableBluetooth != nil {
		disableBT = *host.Hardening.Services.DisableBluetooth
	}
	disableAvahi := false
	if host.Hardening.Services.DisableAvahi != nil {
		disableAvahi = *host.Hardening.Services.DisableAvahi
	}
	disableWifi := false
	if host.Hardening.Services.DisableWifi != nil {
		disableWifi = *host.Hardening.Services.DisableWifi
	}
	mountHardening := false
	if host.Hardening.Filesystem.MountHardening != nil {
		mountHardening = *host.Hardening.Filesystem.MountHardening
	}
	secureShm := false
	if host.Hardening.Filesystem.SecureSharedMemory != nil {
		secureShm = *host.Hardening.Filesystem.SecureSharedMemory
	}
	isStandardPlus := host.Hardening.Level == config.HardeningStandard || host.Hardening.Level == config.HardeningStrict
	accountHardening := isStandardPlus
	banners := isStandardPlus
	ntp := isStandardPlus
	cisBenchmark := false
	if host.Hardening.Kubernetes.CISBenchmark != nil {
		cisBenchmark = *host.Hardening.Kubernetes.CISBenchmark
	}
	appArmorForce := false
	if host.Hardening.Kubernetes.AppArmorForce != nil {
		appArmorForce = *host.Hardening.Kubernetes.AppArmorForce
	}
	usbLockdown := false
	if host.Hardening.Kubernetes.USBLockdown != nil {
		usbLockdown = *host.Hardening.Kubernetes.USBLockdown
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
				"level":               string(host.Hardening.Level),
				"password_auth":       passwordAuth,
				"permit_root_login":   permitRoot,
				"max_auth_tries":      maxAuthTries,
				"allow_users":         allowUsers,
				"ufw_enabled":         ufwEnabled,
				"allow_ssh_from":      allowSSHFrom,
				"rate_limit_ssh":      rateLimitSSH,
				"allow_k3s_ports":     allowK3sPorts,
				"unattended_upgrades": unattendedUpgrades,
				"sysctl_hardening":    sysctlHardening,
				"fail2ban":            fail2ban,
				"auditd":              auditd,
				"disable_bluetooth":   disableBT,
				"disable_avahi":       disableAvahi,
				"disable_wifi":        disableWifi,
				"mount_hardening":     mountHardening,
				"secure_shared_memory": secureShm,
				"account_hardening":   accountHardening,
				"user":                host.User,
				"banners":             banners,
				"ntp":                 ntp,
				"cis_benchmark":       cisBenchmark,
				"apparmor_force":      appArmorForce,
				"usb_lockdown":        usbLockdown,
				"device_profile":      host.DeviceProfile,
				"banner":              banners, // SSH banner also follows banners flag
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
	fmt.Printf("  [%-14s] running ...\r", s.name)

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
		fmt.Printf("  [%-14s] FAILED  (%dms)", s.name, result.DurationMS)
		if len(result.Changed) > 0 {
			fmt.Printf("  changed: %s", strings.Join(result.Changed, ", "))
		}
		fmt.Println()
		return fmt.Errorf("%s", stepFailureMessage(result))
	}

	status := "done"
	if result.Skipped {
		status = "skipped"
	} else if len(result.Changed) > 0 {
		status = "changed"
	}

	fmt.Printf("  [%-14s] %-8s (%dms)", s.name, status, result.DurationMS)
	if len(result.Changed) > 0 {
		fmt.Printf("  changed: %s", strings.Join(result.Changed, ", "))
	}
	fmt.Println()

	return nil
}

func stepFailureMessage(result StepResult) string {
	switch {
	case len(result.Messages) > 0:
		return strings.Join(result.Messages, "; ")
	case len(result.Changed) > 0:
		return "changed: " + strings.Join(result.Changed, ", ")
	default:
		return "step failed"
	}
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

	client, err := internalssh.Connect(host.Address, host.User, host.SSHKey, host.KnownHostsFile, *host.StrictHostKey)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = client.Close() }()

	if err := kubeconfig.Fetch(client, resolveToIP(host.Address), host.Kubeconfig.Context, host.Kubeconfig.Output); err != nil {
		return err
	}

	fmt.Printf("Kubeconfig written to %s\n", host.Kubeconfig.Output)

	if err := mergeKubeconfig(host); err != nil {
		return fmt.Errorf("kubeconfig merge: %w", err)
	}

	if host.Kubeconfig.Merge == nil || !*host.Kubeconfig.Merge {
		fmt.Printf("  kubectl --kubeconfig=%s config use-context %s\n", host.Kubeconfig.Output, host.Kubeconfig.Context)
	}

	return nil
}

// mergeKubeconfig merges the per-host kubeconfig into the shared kubeconfig
// file (typically ~/.kube/config) if host.Kubeconfig.Merge is true.
func mergeKubeconfig(host *config.Host) error {
	if host.Kubeconfig.Merge == nil || !*host.Kubeconfig.Merge {
		return nil
	}
	setCurrent := host.Kubeconfig.SetCurrent != nil && *host.Kubeconfig.SetCurrent
	if err := kubeconfig.Merge(host.Kubeconfig.Output, host.Kubeconfig.MergeInto, host.Kubeconfig.Context, setCurrent); err != nil {
		return err
	}
	fmt.Printf("  Merged context %q into %s\n", host.Kubeconfig.Context, host.Kubeconfig.MergeInto)
	if setCurrent {
		fmt.Printf("  Set current-context to %q\n", host.Kubeconfig.Context)
	}
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

// lookupHost is overridable so tests can inject deterministic address lists.
var lookupHost = net.LookupHost

// resolveToIP resolves a hostname to its first IPv4 address.
// If address is already an IP or resolution fails, it is returned as-is.
// IPv6 link-local addresses are skipped as they are not usable as kubeconfig server addresses.
func resolveToIP(address string) string {
	// If it's already a literal IP, return as-is (covers IPv4 and IPv6 literals).
	if ip := net.ParseIP(address); ip != nil {
		return address
	}
	addrs, err := lookupHost(address)
	if err != nil {
		return address
	}
	// Prefer IPv4
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			return a
		}
	}
	// Fall back to first non-link-local IPv6
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip != nil && !ip.IsLinkLocalUnicast() {
			return a
		}
	}
	return address
}

// FindConfig is the exported version for CLI use.
func FindConfig(explicit string) string {
	return findConfig(explicit)
}
