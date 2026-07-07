// Package cmd provides the cobra command tree for obscura.
package cmd

import (
	"github.com/spf13/cobra"

	"github.com/ivan-khludov/obscura/internal/config"
	"github.com/ivan-khludov/obscura/internal/orchestration"
)

// Options configures the root command.
type Options struct {
	DevMode bool
	JSON    *bool
}

// NewRootCommand builds the obscura command tree.
func NewRootCommand(orch *orchestration.Facade, app *config.App, devMode *bool, opts Options) *cobra.Command {
	_ = app
	jsonFlag := false
	if opts.JSON != nil {
		jsonFlag = *opts.JSON
	}
	jsonVal := jsonFlag
	root := &cobra.Command{
		Use:   "obscura",
		Short: "Terminal manager for sing-box VPN servers",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	if devMode != nil {
		root.PersistentFlags().BoolVar(devMode, "dev", *devMode, "Use development paths under ~/.obscura")
	}
	root.PersistentFlags().BoolVar(&jsonVal, "json", jsonFlag, "JSON output")
	opts.JSON = &jsonVal
	root.AddCommand(newBootstrapCmd(orch, &jsonVal))
	root.AddCommand(newVPNCmd(orch, &jsonVal))
	root.AddCommand(newClientCmd(orch, &jsonVal))
	root.AddCommand(newApplyCmd(orch, &jsonVal))
	root.AddCommand(newRollbackCmd(orch, &jsonVal))
	root.AddCommand(newStatusCmd(orch, &jsonVal))
	root.AddCommand(newDoctorCmd(orch, &jsonVal))
	root.AddCommand(newLogsCmd(&jsonVal))
	root.AddCommand(newBackupCmd(orch, &jsonVal))
	root.AddCommand(newNetworkCmd(orch, &jsonVal))
	root.AddCommand(newSystemCmd(orch, &jsonVal))
	root.AddCommand(newUninstallCmd(orch, &jsonVal))
	root.AddCommand(newVersionCmd(&jsonVal))
	return root
}
