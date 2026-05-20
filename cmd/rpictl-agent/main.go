// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT
// Command rpictl-agent runs provisioning steps on the Raspberry Pi.
// It is uploaded to the Pi by rpictl and invoked via SSH.
//
// Usage: rpictl-agent step <name> --input='{...json...}'
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/idvoretskyi/rpictl/internal/agent"
	"github.com/idvoretskyi/rpictl/internal/version"
)

func main() {
	root := &cobra.Command{
		Use:          "rpictl-agent",
		Short:        "rpictl agent — runs on the Raspberry Pi (uploaded by rpictl)",
		SilenceUsage: true,
	}

	root.AddCommand(newStepCmd())
	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print agent version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("rpictl-agent %s\n", version.Version)
		},
	})

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newStepCmd() *cobra.Command {
	var inputJSON string

	cmd := &cobra.Command{
		Use:   "step <name>",
		Short: "Run a single provisioning step",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			stepName := args[0]
			if inputJSON == "" {
				inputJSON = "{}"
			}

			switch stepName {
			case "preflight":
				agent.Runner(stepName, inputJSON, agent.RunPreflight)
			case "system":
				agent.Runner(stepName, inputJSON, agent.RunSystem)
			case "hardening":
				agent.Runner(stepName, inputJSON, agent.RunHardening)
			case "memory":
				agent.Runner(stepName, inputJSON, agent.RunMemory)
			case "prereqs":
				agent.Runner(stepName, inputJSON, agent.RunPrereqs)
			case "k3s":
				agent.Runner(stepName, inputJSON, agent.RunK3s)
			default:
				return fmt.Errorf("unknown step %q; valid steps: preflight, system, hardening, memory, prereqs, k3s", stepName)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&inputJSON, "input", "{}", "step input as JSON")
	return cmd
}
