package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ivan-khludov/obscura/internal/version"
)

// newVersionCmd returns a Bubble Tea command for async work.
func newVersionCmd(jsonOut *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print obscura version",
		RunE: func(cmd *cobra.Command, args []string) error {
			if *jsonOut {
				return printOK(true, map[string]string{"version": version.Version})
			}
			fmt.Println(version.Version)
			return nil
		},
	}
}
