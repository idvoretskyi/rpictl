// Copyright 2026 Ihor Dvoretskyi
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package cli

import (
	"fmt"

	"github.com/idvoretskyi/rpictl/internal/config"
	"github.com/idvoretskyi/rpictl/internal/orchestrator"
	"github.com/spf13/cobra"
)

func newKubeconfigCmd() *cobra.Command {
	var (
		merge      bool
		noMerge    bool
		setCurrent bool
		mergeInto  string
	)

	cmd := &cobra.Command{
		Use:   "kubeconfig <host>",
		Short: "Fetch kubeconfig from an already-provisioned host and (by default) merge it into ~/.kube/config",
		Args:  cobra.ExactArgs(1),
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

			// Apply CLI overrides. --no-merge takes precedence over --merge.
			if cmd.Flags().Changed("merge") {
				host.Kubeconfig.Merge = &merge
			}
			if cmd.Flags().Changed("no-merge") && noMerge {
				f := false
				host.Kubeconfig.Merge = &f
			}
			if cmd.Flags().Changed("set-current") {
				host.Kubeconfig.SetCurrent = &setCurrent
			}
			if cmd.Flags().Changed("merge-into") {
				host.Kubeconfig.MergeInto = mergeInto
			}

			return orchestrator.FetchKubeconfig(hostName, host)
		},
	}

	cmd.Flags().BoolVar(&merge, "merge", true, "merge fetched kubeconfig into the shared kubeconfig file (default: true)")
	cmd.Flags().BoolVar(&noMerge, "no-merge", false, "do not merge into the shared kubeconfig file")
	cmd.Flags().BoolVar(&setCurrent, "set-current", false, "after merging, set this host's context as the current-context")
	cmd.Flags().StringVar(&mergeInto, "merge-into", "", "shared kubeconfig file to merge into (default: ~/.kube/config)")

	return cmd
}
