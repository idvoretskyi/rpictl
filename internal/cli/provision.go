// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT
package cli

import (
	_ "embed"
	"fmt"

	"github.com/idvoretskyi/rpictl/internal/config"
	"github.com/idvoretskyi/rpictl/internal/orchestrator"
	"github.com/spf13/cobra"
)

//go:embed agent_binary
var agentBinary []byte

func newProvisionCmd() *cobra.Command {
	var force bool
	var hardeningLevel string

	cmd := &cobra.Command{
		Use:   "provision <host>",
		Short: "Provision a Raspberry Pi host defined in rpictl.yaml",
		Long: `provision runs the full provisioning sequence on the named host:

  preflight      → verify aarch64 + Trixie + RAM
  system         → apt upgrade + timezone + hostname
  hardening      → layered security baseline (level: off|basic|standard|strict)
  memory         → zram + swappiness + gpu_mem
  prereqs        → install curl, ca-certificates, gnupg, jq, git
  k3s            → install k3s via get.k3s.io
  harden-verify  → read back controls; write JSON report to ~/.local/share/rpictl/
  kubeconfig     → fetch + rewrite + merge kubeconfig to laptop

Each step is idempotent; re-running provision is safe.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hostName := args[0]
			cfgPath := orchestrator.FindConfig(cfgFile)

			cfg, err := config.Load(cfgPath)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}

			host, err := cfg.GetHost(hostName)
			if err != nil {
				return err
			}

			// CLI flag overrides config-level value
			if cmd.Flags().Changed("hardening-level") {
				host.Hardening.Level = config.HardeningLevel(hardeningLevel)
				// Re-apply defaults with overridden level
				// (applyHardeningDefaults is exported for this purpose)
				config.ApplyHardeningDefaults(host)
			}

			return orchestrator.Provision(hostName, host, agentBinary, force)
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "skip OS version check and untested-device guard")
	cmd.Flags().StringVar(&hardeningLevel, "hardening-level", "", "override hardening level (off|basic|standard|strict)")

	return cmd
}
