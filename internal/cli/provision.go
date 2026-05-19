// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/idvoretskyi/rpictl/internal/config"
	"github.com/idvoretskyi/rpictl/internal/orchestrator"
	_ "embed"
)

//go:embed agent_binary
var agentBinary []byte

func newProvisionCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "provision <host>",
		Short: "Provision a Raspberry Pi host defined in rpictl.yaml",
		Long: `provision runs the full provisioning sequence on the named host:

  preflight   → verify aarch64 + Trixie + RAM
  system      → apt upgrade + timezone + hostname
  hardening   → sshd config + UFW + unattended-upgrades
  memory      → zram + swappiness + gpu_mem
  prereqs     → install curl, ca-certificates, gnupg, jq, git
  k3s         → install k3s via get.k3s.io
  kubeconfig  → fetch + rewrite kubeconfig to laptop

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

			return orchestrator.Provision(hostName, host, agentBinary, force)
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "skip OS version check and untested-device guard")

	return cmd
}
