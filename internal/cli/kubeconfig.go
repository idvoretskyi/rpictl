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

	"github.com/spf13/cobra"
	"github.com/idvoretskyi/rpictl/internal/config"
	"github.com/idvoretskyi/rpictl/internal/orchestrator"
)

func newKubeconfigCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "kubeconfig <host>",
		Short: "Fetch and write kubeconfig from an already-provisioned host",
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

			return orchestrator.FetchKubeconfig(hostName, host)
		},
	}
}
