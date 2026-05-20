// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	cfgFile string
)

// NewRootCmd returns the root cobra command.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "rpictl",
		Short: "Provisioning CLI for Raspberry Pi single-node k3s clusters",
		Long: `rpictl provisions Raspberry Pi boards (3B, 3B+, 4, 5) with a
single-node k3s cluster. It uploads a small agent binary to the Pi,
runs idempotent provisioning steps over SSH, and writes a kubeconfig
to your laptop.

Supported devices: RPi 3B, 3B+ (tested), RPi 4, RPi 5 (untested, best-effort)
OS requirement:    Raspberry Pi OS Lite, Debian 13 Trixie`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "path to rpictl.yaml (default: ./rpictl.yaml)")

	root.AddCommand(newVersionCmd())
	root.AddCommand(newProvisionCmd())
	root.AddCommand(newKubeconfigCmd())
	root.AddCommand(newUnhardenCmd())

	return root
}

// Execute runs the root command and exits on error.
func Execute() {
	if err := NewRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
