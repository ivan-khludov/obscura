package cmd

import (
	"github.com/spf13/cobra"

	"github.com/ivan-khludov/obscura/internal/orchestration"
)

type vlessFlagValues struct {
	DefaultFlow string
}

// bindVlessFlags binds CLI flags to command options.
func bindVlessFlags(cmd *cobra.Command, v *vlessFlagValues) {
	cmd.Flags().StringVar(&v.DefaultFlow, "vless-flow", "", "Default VLESS flow (xtls-rprx-vision for direct TLS)")
}

// readVlessInput performs an internal helper operation.
func readVlessInput(t trojanFlagValues, v vlessFlagValues, multiplex, multiplexPadding, multiplexBrutal bool, brutalUp, brutalDown int) orchestration.VLESSCreateOptions {
	base := orchestration.VLESSCreateOptions{DefaultFlow: v.DefaultFlow}
	tIn := readTrojanInput(t, multiplex, multiplexPadding)
	return orchestration.BuildVLESSCreateOptions(base, tIn, multiplexBrutal, brutalUp, brutalDown)
}
