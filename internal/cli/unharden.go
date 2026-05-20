// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT
package cli

import (
	"fmt"
	"strings"

	"github.com/idvoretskyi/rpictl/internal/config"
	"github.com/idvoretskyi/rpictl/internal/orchestrator"
	"github.com/spf13/cobra"
)

func newUnhardenCmd() *cobra.Command {
	var layerFlags []string
	var all bool

	cmd := &cobra.Command{
		Use:   "unharden <host>",
		Short: "Reverse hardening applied by rpictl on an already-provisioned host",
		Long: `unharden connects to the host via SSH and reverses the hardening layers
that were applied by rpictl provision. By default all layers are reversed.

Use --layer to reverse only specific layers:
  rpictl unharden rpi3 --layer=ssh --layer=ufw

Available layer names: ssh, firewall, sysctl, fail2ban, auditd, mounts,
  services, accounts, banners, ntp, k3s-cis, apparmor-usb`,
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

			layers := layerFlags
			if all || len(layers) == 0 {
				layers = nil // empty = all layers in agent
			}

			fmt.Printf("Unhardening host %q", hostName)
			if len(layers) > 0 {
				fmt.Printf(" (layers: %s)", strings.Join(layers, ", "))
			} else {
				fmt.Printf(" (all layers)")
			}
			fmt.Println()

			return orchestrator.Unharden(hostName, host, agentBinary, layers)
		},
	}

	cmd.Flags().StringArrayVar(&layerFlags, "layer", nil, "layer to unharden (may be specified multiple times)")
	cmd.Flags().BoolVar(&all, "all", false, "unharden all layers (default when no --layer specified)")

	return cmd
}
