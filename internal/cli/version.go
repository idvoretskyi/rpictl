// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/idvoretskyi/rpictl/internal/version"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print rpictl version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("rpictl %s\n", version.Version)
		},
	}
}
