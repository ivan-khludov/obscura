package cmd

import (
	"github.com/spf13/cobra"

	"github.com/ivan-khludov/obscura/internal/orchestration"
)

type vmessFlagValues struct {
	DefaultAlterId int
	NoTLS          bool
}

// bindVmessFlags binds CLI flags to command options.
func bindVmessFlags(cmd *cobra.Command, v *vmessFlagValues) {
	cmd.Flags().IntVar(&v.DefaultAlterId, "vmess-alter-id", 0, "Default VMess alterId for new clients (0 recommended)")
	cmd.Flags().BoolVar(&v.NoTLS, "vmess-no-tls", false, "Disable TLS for VMess inbound")
}

// readVmessInput performs an internal helper operation.
func readVmessInput(t trojanFlagValues, v vmessFlagValues, multiplex, multiplexPadding, multiplexBrutal bool, brutalUp, brutalDown int) orchestration.VMessCreateOptions {
	base := orchestration.VMessCreateOptions{
		DefaultAlterId: v.DefaultAlterId,
		NoTLS:          v.NoTLS,
	}
	tIn := readTrojanInput(t, multiplex, multiplexPadding)
	return orchestration.BuildVMessCreateOptions(base, tIn, multiplexBrutal, brutalUp, brutalDown)
}
