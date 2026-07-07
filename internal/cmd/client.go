package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/qr"
)

// newClientCmd builds the client subcommand tree.
func newClientCmd(orch *orchestration.Facade, jsonOut *bool) *cobra.Command {
	client := &cobra.Command{Use: "client", Short: "Manage VPN clients"}

	addCmd := &cobra.Command{
		Use:   "add",
		Short: "Add a client to a VPN",
		RunE: func(cmd *cobra.Command, args []string) error {
			vpnName, _ := cmd.Flags().GetString("vpn")
			name, _ := cmd.Flags().GetString("name")
			noApply, _ := cmd.Flags().GetBool("no-apply")
			showQR, _ := cmd.Flags().GetBool("qr")
			result, err := orch.AddClientFromRequest(cmd.Context(), orchestration.AddClientRequest{
				VPNName: vpnName,
				Name:    name,
				Reapply: !noApply,
			})
			if err != nil {
				return err
			}
			return clientAddAfterCreate(cmd.Context(), orch, *jsonOut, vpnName, name, showQR, result.Client, result.URI)
		},
	}
	addCmd.Flags().String("vpn", "", "VPN name")
	addCmd.Flags().String("name", "", "Client name")
	addCmd.Flags().Bool("no-apply", false, "Skip apply after add")
	addCmd.Flags().Bool("qr", false, "Print QR code")
	_ = addCmd.MarkFlagRequired("vpn")
	_ = addCmd.MarkFlagRequired("name")

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List clients for a VPN",
		RunE: func(cmd *cobra.Command, args []string) error {
			vpn, _ := cmd.Flags().GetString("vpn")
			result, err := orch.ListClientsFromRequest(cmd.Context(), orchestration.ListClientsRequest{VPNName: vpn})
			if err != nil {
				return err
			}
			return printOK(*jsonOut, result.Items)
		},
	}
	listCmd.Flags().String("vpn", "", "VPN name")
	_ = listCmd.MarkFlagRequired("vpn")

	showCmd := &cobra.Command{
		Use:   "show",
		Short: "Show client connection URI",
		RunE: func(cmd *cobra.Command, args []string) error {
			vpn, _ := cmd.Flags().GetString("vpn")
			name, _ := cmd.Flags().GetString("name")
			showQR, _ := cmd.Flags().GetBool("qr")
			clientData, err := orch.ShowClientFromRequest(cmd.Context(), orchestration.ShowClientRequest{
				VPNName:   vpn,
				Name:      name,
				IncludeQR: showQR,
			})
			if err != nil {
				return err
			}
			return outputClientURI(*jsonOut, nil, clientData.URI, clientData.QRContent, showQR)
		},
	}
	showCmd.Flags().String("vpn", "", "VPN name")
	showCmd.Flags().String("name", "", "Client name")
	showCmd.Flags().Bool("qr", false, "Print QR code")
	_ = showCmd.MarkFlagRequired("vpn")
	_ = showCmd.MarkFlagRequired("name")

	removeCmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove a client",
		RunE: func(cmd *cobra.Command, args []string) error {
			vpn, _ := cmd.Flags().GetString("vpn")
			name, _ := cmd.Flags().GetString("name")
			_, err := orch.RemoveClientFromRequest(cmd.Context(), orchestration.RemoveClientRequest{VPNName: vpn, Name: name})
			return err
		},
	}
	removeCmd.Flags().String("vpn", "", "VPN name")
	removeCmd.Flags().String("name", "", "Client name")
	_ = removeCmd.MarkFlagRequired("vpn")
	_ = removeCmd.MarkFlagRequired("name")

	rotateCmd := &cobra.Command{
		Use:   "rotate-password",
		Short: "Rotate client password",
		RunE: func(cmd *cobra.Command, args []string) error {
			vpn, _ := cmd.Flags().GetString("vpn")
			name, _ := cmd.Flags().GetString("name")
			showQR, _ := cmd.Flags().GetBool("qr")
			result, err := orch.RotateClientPasswordFromRequest(cmd.Context(), orchestration.RotateClientPasswordRequest{
				VPNName:   vpn,
				Name:      name,
				IncludeQR: showQR,
			})
			if err != nil {
				return err
			}
			if *jsonOut {
				return printOK(true, map[string]string{"password": result.Password, "uri": result.URI})
			}
			fmt.Println(result.URI)
			if showQR {
				return printClientQR(result.URI, result.QRContent)
			}
			return nil
		},
	}
	rotateCmd.Flags().String("vpn", "", "VPN name")
	rotateCmd.Flags().String("name", "", "Client name")
	rotateCmd.Flags().Bool("qr", false, "Print QR code")
	_ = rotateCmd.MarkFlagRequired("vpn")
	_ = rotateCmd.MarkFlagRequired("name")

	editCmd := &cobra.Command{
		Use:   "edit",
		Short: "Edit a client",
		RunE: func(cmd *cobra.Command, args []string) error {
			vpnName, _ := cmd.Flags().GetString("vpn")
			name, _ := cmd.Flags().GetString("name")
			var newNameValue *string
			if newName, _ := cmd.Flags().GetString("new-name"); newName != "" {
				newNameValue = &newName
			}
			var usernameValue *string
			if cmd.Flags().Changed("username") {
				username, _ := cmd.Flags().GetString("username")
				usernameValue = &username
			}
			var passwordValue *string
			if cmd.Flags().Changed("password") {
				password, _ := cmd.Flags().GetString("password")
				passwordValue = &password
			}
			var enabledValue *bool
			if cmd.Flags().Changed("enabled") {
				enabled, _ := cmd.Flags().GetBool("enabled")
				enabledValue = &enabled
			}
			if cmd.Flags().Changed("disabled") {
				disabled, _ := cmd.Flags().GetBool("disabled")
				if disabled {
					enabled := false
					enabledValue = &enabled
				}
			}
			updateReq := orchestration.UpdateClientRequest{
				VPNName:  vpnName,
				Name:     name,
				NewName:  newNameValue,
				Username: usernameValue,
				Password: passwordValue,
				Enabled:  enabledValue,
			}
			reapply, _ := cmd.Flags().GetBool("apply")
			updateReq.Reapply = reapply
			result, err := orch.UpdateClientFromRequest(cmd.Context(), updateReq)
			if err != nil {
				return err
			}
			return printOK(*jsonOut, result.Client)
		},
	}
	editCmd.Flags().String("vpn", "", "VPN name")
	editCmd.Flags().String("name", "", "Client name")
	editCmd.Flags().String("new-name", "", "Rename client")
	editCmd.Flags().String("username", "", "New username")
	editCmd.Flags().String("password", "", "New password")
	editCmd.Flags().Bool("enabled", false, "Enable client")
	editCmd.Flags().Bool("disabled", false, "Disable client")
	editCmd.Flags().Bool("apply", true, "Apply configuration after edit")
	_ = editCmd.MarkFlagRequired("vpn")
	_ = editCmd.MarkFlagRequired("name")

	client.AddCommand(addCmd, listCmd, showCmd, removeCmd, rotateCmd, editCmd)
	return client
}

func fetchClientQRForAdd(ctx context.Context, orch *orchestration.Facade, vpnName, name string) (string, error) {
	clientData, err := orch.ShowClientFromRequest(ctx, orchestration.ShowClientRequest{
		VPNName:   vpnName,
		Name:      name,
		IncludeQR: true,
	})
	if err != nil {
		return "", err
	}
	return clientData.QRContent, nil
}

func clientAddAfterCreate(ctx context.Context, orch *orchestration.Facade, jsonOut bool, vpnName, name string, showQR bool, client any, uri string) error {
	var qrContent string
	if showQR {
		var err error
		qrContent, err = fetchClientQRForAdd(ctx, orch, vpnName, name)
		if err != nil {
			return err
		}
	}
	return outputClientURI(jsonOut, client, uri, qrContent, showQR)
}

// outputClientURI prints or encodes a client connection URI and optional QR code.
func outputClientURI(asJSON bool, client any, uri, qrContent string, showQR bool) error {
	if asJSON {
		if client != nil {
			return printOK(true, map[string]any{"client": client, "uri": uri})
		}
		return printOK(true, map[string]string{"uri": uri})
	}
	fmt.Println(uri)
	if showQR {
		return printClientQR(uri, qrContent)
	}
	return nil
}

// printClientQR renders QR content; uses qrContent when it differs from the display URI.
func printClientQR(uri, qrContent string) error {
	content := uri
	if qrContent != "" && qrContent != uri {
		content = qrContent
	}
	return printQR(content)
}

// printQR renders content as a terminal QR code to stdout.
func printQR(content string) error {
	ascii, err := qr.Terminal(content)
	if err != nil {
		return err
	}
	fmt.Println(ascii)
	return nil
}
