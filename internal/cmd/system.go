package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ivan-khludov/obscura/internal/doctor"
	"github.com/ivan-khludov/obscura/internal/logs"
	"github.com/ivan-khludov/obscura/internal/orchestration"
)

// newBootstrapCmd builds the bootstrap subcommand.
func newBootstrapCmd(orch *orchestration.Facade, jsonOut *bool) *cobra.Command {
	var yes bool
	var withFallbackStub bool
	cmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "Initialize obscura on this server",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !yes {
				fmt.Print("Bootstrap will install sing-box, configure kernel tuning, and create /etc/obscura. Continue? [y/N] ")
				var answer string
				_, _ = fmt.Scanln(&answer)
				if answer != "y" && answer != "Y" {
					return nil
				}
			}
			if _, err := orch.BootstrapFromRequest(cmd.Context(), orchestration.BootstrapRequest{WithFallbackStub: withFallbackStub}); err != nil {
				return err
			}
			return printOK(*jsonOut, map[string]string{"status": "bootstrapped"})
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "Skip confirmation")
	cmd.Flags().BoolVar(&withFallbackStub, "with-fallback-stub", false, "Install Caddy HTTP stub on 127.0.0.1:8080 for Trojan TLS inbound fallback")
	return cmd
}

// newApplyCmd builds the apply subcommand.
func newApplyCmd(orch *orchestration.Facade, jsonOut *bool) *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Render and apply sing-box configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := orch.ApplyFromRequest(cmd.Context(), orchestration.ApplyRequest{DryRun: dryRun})
			if err != nil {
				return err
			}
			return printOK(*jsonOut, result)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Validate without writing")
	return cmd
}

// newRollbackCmd builds the rollback subcommand.
func newRollbackCmd(orch *orchestration.Facade, _ *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "rollback",
		Short: "Rollback to previous sing-box configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := orch.RollbackFromRequest(cmd.Context(), orchestration.RollbackRequest{})
			return err
		},
	}
}

// newStatusCmd builds the status subcommand.
func newStatusCmd(orch *orchestration.Facade, jsonOut *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show obscura status summary",
		RunE: func(cmd *cobra.Command, args []string) error {
			info, err := orch.StatusFromRequest(cmd.Context(), orchestration.StatusRequest{})
			if err != nil {
				return err
			}
			return printOK(*jsonOut, info)
		},
	}
}

// newDoctorCmd builds the doctor subcommand.
func newDoctorCmd(orch *orchestration.Facade, jsonOut *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Run server health checks",
		RunE: func(cmd *cobra.Command, args []string) error {
			results, err := orch.DoctorFromRequest(cmd.Context(), orchestration.DoctorRequest{FailOnFailures: !*jsonOut})
			return formatDoctorResults(*jsonOut, results, err)
		},
	}
}

func formatDoctorResults(jsonOut bool, results []doctor.CheckResult, err error) error {
	if err != nil && !jsonOut {
		for _, r := range results {
			fmt.Printf("[%s] %s: %s\n", r.Status, r.Name, r.Message)
		}
		return err
	}
	if err != nil {
		return err
	}
	if jsonOut {
		return printOK(true, results)
	}
	for _, r := range results {
		fmt.Printf("[%s] %s: %s\n", r.Status, r.Name, r.Message)
	}
	return nil
}

// newLogsCmd builds the logs subcommand.
func newLogsCmd(_ *bool) *cobra.Command {
	var follow bool
	var since string
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Show sing-box service logs",
		RunE: func(cmd *cobra.Command, args []string) error {
			reader := logs.NewReader()
			return reader.Print(cmd.Context(), os.Stdout, follow, since)
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow log output")
	cmd.Flags().StringVar(&since, "since", "1 hour ago", "Show logs since timestamp")
	return cmd
}

// newBackupCmd builds the backup subcommand tree.
func newBackupCmd(orch *orchestration.Facade, jsonOut *bool) *cobra.Command {
	backupCmd := &cobra.Command{Use: "backup", Short: "Backup and restore obscura state"}
	backupCmd.AddCommand(&cobra.Command{
		Use:   "create",
		Short: "Create a backup archive",
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := orch.CreateBackupFromRequest(cmd.Context(), orchestration.CreateBackupRequest{})
			if err != nil {
				return err
			}
			return printOK(*jsonOut, map[string]string{"path": result.Path})
		},
	})
	backupCmd.AddCommand(&cobra.Command{
		Use:   "restore [archive]",
		Short: "Restore from a backup archive",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := orch.RestoreBackupFromRequest(cmd.Context(), orchestration.RestoreBackupRequest{ArchivePath: args[0]})
			return err
		},
	})
	return backupCmd
}

// newUninstallCmd builds the uninstall subcommand.
func newUninstallCmd(orch *orchestration.Facade, jsonOut *bool) *cobra.Command {
	var dryRun, full, wipe bool
	var confirm string
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove obscura-managed resources",
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := orch.UninstallFromRequest(cmd.Context(), orchestration.UninstallRequest{
				DryRun:   dryRun,
				Full:     full,
				Confirm:  confirm,
				WipeData: wipe,
			})
			if err != nil {
				return err
			}
			if dryRun {
				return printOK(*jsonOut, result.Plan)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview uninstall actions")
	cmd.Flags().BoolVar(&full, "full", false, "Perform full uninstall")
	cmd.Flags().BoolVar(&wipe, "wipe-data", false, "Remove entire data directory")
	cmd.Flags().StringVar(&confirm, "confirm", "", "Type 'destroy' to confirm full uninstall")
	return cmd
}

// newNetworkCmd builds network tuning subcommands.
func newNetworkCmd(orch *orchestration.Facade, jsonOut *bool) *cobra.Command {
	network := &cobra.Command{Use: "network", Short: "Network tuning"}
	congestion := &cobra.Command{Use: "congestion", Short: "TCP congestion control"}
	congestion.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List available TCP congestion control algorithms",
		RunE: func(cmd *cobra.Command, args []string) error {
			result, _ := orch.NetworkCongestionFromRequest(cmd.Context(), orchestration.NetworkCongestionRequest{})
			if *jsonOut {
				return printOK(true, map[string]any{"current": result.Current, "available": result.Available})
			}
			fmt.Printf("current: %s\n", result.Current)
			for _, item := range result.Available {
				fmt.Println(item)
			}
			return nil
		},
	})
	congestion.AddCommand(&cobra.Command{
		Use:   "set [algorithm]",
		Short: "Set TCP congestion control algorithm",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := orch.SetCongestionFromRequest(cmd.Context(), orchestration.SetCongestionRequest{Algorithm: args[0]})
			if err != nil {
				return err
			}
			return printOK(*jsonOut, map[string]string{
				"congestion_control": result.Algorithm,
			})
		},
	})
	network.AddCommand(congestion)
	return network
}

// printOK writes v as JSON or Go-syntax text to stdout.
func printOK(asJSON bool, v any) error {
	if asJSON {
		return jsonNewEncoder(os.Stdout).Encode(v)
	}
	fmt.Printf("%+v\n", v)
	return nil
}
