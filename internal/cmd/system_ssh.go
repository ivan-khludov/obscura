package cmd

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/ivan-khludov/obscura/internal/orchestration"
)

// newSystemCmd returns a Bubble Tea command for async work.
func newSystemCmd(orch *orchestration.Facade, jsonOut *bool) *cobra.Command {
	system := &cobra.Command{Use: "system", Short: "System configuration"}

	ssh := &cobra.Command{Use: "ssh", Short: "OpenSSH server settings"}

	port := &cobra.Command{
		Use:   "port",
		Short: "Show or set SSH listen port",
		RunE: func(cmd *cobra.Command, args []string) error {
			result, _ := orch.GetSSHPortFromRequest(cmd.Context(), orchestration.SSHPortReadRequest{})
			p := result.Port
			if *jsonOut {
				return printOK(true, map[string]int{"ssh_port": p})
			}
			fmt.Println(p)
			return nil
		},
	}

	portSet := &cobra.Command{
		Use:   "set [port]",
		Short: "Set SSH listen port (updates sshd_config and reloads ssh)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := strconv.Atoi(args[0])
			if err != nil {
				return fmt.Errorf("invalid port %q", args[0])
			}
			if _, err := orch.SetSSHPortFromRequest(cmd.Context(), orchestration.SetSSHPortRequest{Port: p}); err != nil {
				return err
			}
			return printOK(*jsonOut, map[string]int{"ssh_port": p})
		},
	}

	port.AddCommand(portSet)
	ssh.AddCommand(port)
	system.AddCommand(ssh)
	return system
}
