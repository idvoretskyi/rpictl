// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT
package agent

import (
	"fmt"
	"os"
	"strings"
)

const sysctlHardeningPath = "/etc/sysctl.d/99-rpictl-hardening.conf"

// sysctlHardeningContent is the sysctl drop-in applied at standard+ levels.
// IMPORTANT: net.ipv4.ip_forward and net.bridge.bridge-nf-call-iptables are
// NOT included — k3s/flannel requires both and they must remain at their
// runtime values.
const sysctlHardeningContent = `# Managed by rpictl — do not edit manually
# Layer 3 — Kernel sysctl hardening

# Restrict kernel pointer exposure
kernel.kptr_restrict = 2

# Restrict dmesg access to root
kernel.dmesg_restrict = 1

# Restrict ptrace to parent processes
kernel.yama.ptrace_scope = 2

# Disable unprivileged BPF
kernel.unprivileged_bpf_disabled = 1

# Reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable ICMP redirect acceptance and sending
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Log martians
net.ipv4.conf.all.log_martians = 1

# SYN cookies for SYN flood protection
net.ipv4.tcp_syncookies = 1

# IPv6 redirect hardening
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Filesystem protection
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# NOTE: net.ipv4.ip_forward is intentionally NOT set here.
# NOTE: net.bridge.bridge-nf-call-iptables is intentionally NOT set here.
# k3s/flannel requires both; they are managed by k3s at runtime.
`

// applySysctlHardening applies Layer 3 — kernel sysctl hardening.
func applySysctlHardening(input StepInput) ([]string, []string, error) {
	enabled := boolVal(boolPtr(input, "sysctl_hardening"), false)
	if !enabled {
		return nil, nil, nil
	}

	hash := inputHash(fmt.Sprintf("%v", input["sysctl_hardening"]))
	if hardeningMarkerExists("sysctl", hash) {
		return nil, []string{"sysctl: already applied"}, nil
	}

	if err := backupFile(sysctlHardeningPath); err != nil {
		return nil, nil, fmt.Errorf("backup sysctl config: %w", err)
	}

	safeSysctl, err := validateHardeningPath(sysctlHardeningPath)
	if err != nil {
		return nil, nil, fmt.Errorf("validate sysctl path: %w", err)
	}
	if err := os.WriteFile(safeSysctl, []byte(sysctlHardeningContent), 0644); err != nil { // #nosec G306 -- sysctl.d configs must be world-readable (sysctl reads them during boot)
		return nil, nil, fmt.Errorf("write sysctl config: %w", err)
	}

	// Apply immediately without reboot
	if _, err := runCommand("sysctl", "--system"); err != nil {
		return nil, nil, fmt.Errorf("sysctl --system: %w", err)
	}

	writeHardeningMarker("sysctl", hash)
	return []string{"sysctl-hardening"}, []string{"sysctl: kernel hardening applied"}, nil
}

// unhardenSysctl removes the sysctl drop-in and re-loads system sysctls.
func unhardenSysctl() error {
	if err := restoreFile(sysctlHardeningPath); err != nil {
		return fmt.Errorf("restore sysctl config: %w", err)
	}
	// Remove our file if no backup existed (restore is a no-op then)
	_ = os.Remove(sysctlHardeningPath)
	if _, err := runCommand("sysctl", "--system"); err != nil {
		return fmt.Errorf("sysctl --system after restore: %w", err)
	}
	removeHardeningMarker("sysctl")
	return nil
}

// SysctlHardeningContent returns the expected content for tests.
func SysctlHardeningContent() string {
	return strings.TrimSpace(sysctlHardeningContent)
}
