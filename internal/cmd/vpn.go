package cmd

import (
	"github.com/spf13/cobra"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/orchestration"
)

// newVPNCmd builds the vpn subcommand tree.
func newVPNCmd(orch *orchestration.Facade, jsonOut *bool) *cobra.Command {
	vpn := &cobra.Command{Use: "vpn", Short: "Manage VPN instances"}

	createListen := domain.DefaultListenOptions()
	var trojanFlags trojanFlagValues
	var wireguardFlags wireguardFlagValues
	var vmessFlags vmessFlagValues
	var vlessFlags vlessFlagValues
	var hysteria2Flags hysteria2FlagValues
	var tuicFlags tuicFlagValues
	var fallbackStub bool
	var multiplexBrutal bool
	var multiplexBrutalUpMbps int
	var multiplexBrutalDownMbps int
	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a VPN instance",
		RunE: func(cmd *cobra.Command, args []string) error {
			name, _ := cmd.Flags().GetString("name")
			protocolName, _ := cmd.Flags().GetString("protocol")
			enabled, _ := cmd.Flags().GetBool("enabled")
			clientName, _ := cmd.Flags().GetString("client-name")
			httpTLS, _ := cmd.Flags().GetBool("tls")
			ssMethod, _ := cmd.Flags().GetString("method")
			ssPlugin, _ := cmd.Flags().GetString("plugin")
			ssPluginOpts, _ := cmd.Flags().GetString("plugin-opts")
			ssMultiplex, _ := cmd.Flags().GetBool("multiplex")
			ssMultiplexPadding, _ := cmd.Flags().GetBool("multiplex-padding")
			multiplexBrutal, _ = cmd.Flags().GetBool("multiplex-brutal")
			multiplexBrutalUpMbps, _ = cmd.Flags().GetInt("multiplex-brutal-up-mbps")
			multiplexBrutalDownMbps, _ = cmd.Flags().GetInt("multiplex-brutal-down-mbps")
			ssShadowTLS, _ := cmd.Flags().GetBool("shadowtls")
			ssShadowTLSHandshake, _ := cmd.Flags().GetString("shadowtls-handshake")
			ssShadowTLSHandshakePort, _ := cmd.Flags().GetInt("shadowtls-handshake-port")
			ssShadowTLSStrictMode, _ := cmd.Flags().GetBool("shadowtls-strict-mode")
			applyFallbackStub(&trojanFlags, fallbackStub)
			if !cmd.Flags().Changed("port") {
				createListen.ListenPort = 0
			}
			clientHost, _ := cmd.Flags().GetString("client-host")
			sharedInboundMultiplex := ssMultiplex && (protocolName == "trojan" || protocolName == "vmess" || protocolName == "vless")
			sharedInboundMultiplexPadding := ssMultiplexPadding && (protocolName == "trojan" || protocolName == "vmess" || protocolName == "vless")
			createReq := orchestration.CreateVPNRequest{
				Name:                     name,
				Protocol:                 protocolName,
				ClientHost:               clientHost,
				Listen:                   createListen,
				Enabled:                  enabled,
				InitialClientName:        clientName,
				HTTPTLS:                  httpTLS,
				SSMethod:                 ssMethod,
				SSPlugin:                 ssPlugin,
				SSPluginOpts:             ssPluginOpts,
				SSMultiplex:              ssMultiplex,
				SSMultiplexPadding:       ssMultiplexPadding,
				SSShadowTLS:              ssShadowTLS,
				SSShadowTLSHandshake:     ssShadowTLSHandshake,
				SSShadowTLSHandshakePort: ssShadowTLSHandshakePort,
				SSShadowTLSStrictMode:    ssShadowTLSStrictMode,
				HTTP:                     orchestration.HTTPCreateOptions{TLS: httpTLS},
				Shadowsocks: orchestration.BuildShadowsocksCreateOptions(
					ssMethod,
					ssPlugin,
					ssPluginOpts,
					ssMultiplex,
					ssMultiplexPadding,
					ssShadowTLS,
					ssShadowTLSHandshake,
					ssShadowTLSHandshakePort,
					ssShadowTLSStrictMode,
					createListen.ListenPort,
				),
				Trojan: orchestration.BuildTrojanCreateOptions(
					trojanFlags.TrojanCreateOptions,
					sharedInboundMultiplex,
					sharedInboundMultiplexPadding,
					fallbackStub,
				),
				Wireguard: readWireguardInput(wireguardFlags),
				VMess: readVmessInput(
					trojanFlags,
					vmessFlags,
					sharedInboundMultiplex,
					sharedInboundMultiplexPadding,
					multiplexBrutal,
					multiplexBrutalUpMbps,
					multiplexBrutalDownMbps,
				),
				VLESS: readVlessInput(
					trojanFlags,
					vlessFlags,
					sharedInboundMultiplex,
					sharedInboundMultiplexPadding,
					multiplexBrutal,
					multiplexBrutalUpMbps,
					multiplexBrutalDownMbps,
				),
				Hysteria2:                        readHysteria2Input(hysteria2Flags),
				TUIC:                             readTUICInput(tuicFlags),
				MultiplexRequested:               ssMultiplex,
				MultiplexPaddingRequested:        ssMultiplexPadding,
				MultiplexBrutalRequested:         multiplexBrutal,
				MultiplexBrutalUpMbpsRequested:   multiplexBrutalUpMbps,
				MultiplexBrutalDownMbpsRequested: multiplexBrutalDownMbps,
			}
			result, err := orch.CreateVPNFromRequest(cmd.Context(), createReq)
			if err != nil {
				return err
			}
			return printOK(*jsonOut, result)
		},
	}
	createCmd.Flags().String("name", "", "VPN name")
	createCmd.Flags().String("protocol", "socks5", "Protocol type (http, socks5, shadowsocks, trojan, wireguard, vmess, vless, hysteria2, tuic)")
	createCmd.Flags().Bool("enabled", true, "Enable VPN")
	createCmd.Flags().String("client-name", "", "Initial client name (default: default)")
	createCmd.Flags().String("client-host", "", "Client connect host or IP for share links (default: server hostname)")
	createCmd.Flags().Bool("tls", false, "Enable TLS with self-signed certificate (http only)")
	createCmd.Flags().String("method", "", "Shadowsocks cipher (default: 2022-blake3-aes-128-gcm)")
	createCmd.Flags().String("plugin", "", "Shadowsocks SIP003 plugin for client URI only (not applied to server inbound)")
	createCmd.Flags().String("plugin-opts", "", "Shadowsocks plugin options")
	createCmd.Flags().Bool("multiplex", false, "Enable sing-box multiplex (shadowsocks, trojan, or vmess)")
	createCmd.Flags().Bool("multiplex-padding", false, "Require padded multiplex connections (shadowsocks, trojan, or vmess)")
	createCmd.Flags().Bool("multiplex-brutal", false, "Enable TCP brutal in multiplex (vmess or vless)")
	createCmd.Flags().Int("multiplex-brutal-up-mbps", 0, "Multiplex brutal upload bandwidth in Mbps")
	createCmd.Flags().Int("multiplex-brutal-down-mbps", 0, "Multiplex brutal download bandwidth in Mbps")
	createCmd.Flags().Bool("shadowtls", false, "Front Shadowsocks with ShadowTLS v3")
	createCmd.Flags().String("shadowtls-handshake", "", "ShadowTLS handshake server (default: www.bing.com)")
	createCmd.Flags().Int("shadowtls-handshake-port", 0, "ShadowTLS handshake port (default: 443)")
	createCmd.Flags().Bool("shadowtls-strict-mode", false, "Enable ShadowTLS strict mode")
	bindListenFlags(createCmd, &createListen)
	bindTrojanFlags(createCmd, &trojanFlags)
	bindWireguardFlags(createCmd, &wireguardFlags)
	bindVmessFlags(createCmd, &vmessFlags)
	bindVlessFlags(createCmd, &vlessFlags)
	bindHysteria2Flags(createCmd, &hysteria2Flags)
	bindTUICFlags(createCmd, &tuicFlags)
	createCmd.Flags().BoolVar(&fallbackStub, "fallback-stub", false, "Enable Trojan TLS fallback to local stub (127.0.0.1:8080)")
	_ = createCmd.MarkFlagRequired("name")

	editListen := domain.DefaultListenOptions()
	editCmd := &cobra.Command{
		Use:   "edit [name]",
		Short: "Edit a VPN instance",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			vpnRecord, err := orch.GetVPNFromRequest(cmd.Context(), orchestration.GetVPNRequest{Name: name})
			if err != nil {
				return err
			}
			editListen = orchestration.ApplyListenPatch(vpnRecord.VPN.Listen, orchestration.ListenPatch{
				Listen:               stringPtrFromFlag(cmd, "listen"),
				ListenPort:           intPtrFromFlag(cmd, "port"),
				BindInterface:        stringPtrFromFlag(cmd, "bind-interface"),
				RoutingMark:          stringPtrFromFlag(cmd, "routing-mark"),
				ReuseAddr:            boolPtrFromFlag(cmd, "reuse-addr"),
				Netns:                stringPtrFromFlag(cmd, "netns"),
				TCPFastOpen:          boolPtrFromFlag(cmd, "tcp-fast-open"),
				TCPMultiPath:         boolPtrFromFlag(cmd, "tcp-multi-path"),
				DisableTCPKeepAlive:  boolPtrFromFlag(cmd, "disable-tcp-keep-alive"),
				TCPKeepAlive:         stringPtrFromFlag(cmd, "tcp-keep-alive"),
				TCPKeepAliveInterval: stringPtrFromFlag(cmd, "tcp-keep-alive-interval"),
				UDPFragment:          boolPtrFromFlag(cmd, "udp-fragment"),
				UDPTimeout:           stringPtrFromFlag(cmd, "udp-timeout"),
				Detour:               stringPtrFromFlag(cmd, "detour"),
			})
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
			tlsEnableRequested := cmd.Flags().Changed("tls")
			tlsDisableRequested := false
			if cmd.Flags().Changed("no-tls") {
				noTLS, _ := cmd.Flags().GetBool("no-tls")
				if noTLS {
					tlsDisableRequested = true
				}
			}
			var newNameValue *string
			newName, _ := cmd.Flags().GetString("new-name")
			if newName != "" {
				newNameValue = &newName
			}
			var clientHostValue *string
			clearClientHost := false
			if cmd.Flags().Changed("clear-client-host") {
				clearClientHost = true
			} else if cmd.Flags().Changed("client-host") {
				clientHost, _ := cmd.Flags().GetString("client-host")
				clientHostValue = &clientHost
			}
			reapply, _ := cmd.Flags().GetBool("apply")
			updated, err := orch.EditVPNFromRequest(cmd.Context(), orchestration.EditVPNRequest{
				VPNName:  name,
				Protocol: vpnRecord.VPN.Protocol,
				Update: orchestration.UpdateVPNRequest{
					Name:            newNameValue,
					Listen:          &editListen,
					Enabled:         enabledValue,
					ClientHost:      clientHostValue,
					ClearClientHost: clearClientHost,
				},
				TLSEnableRequested:  tlsEnableRequested,
				TLSDisableRequested: tlsDisableRequested,
				Reapply:             reapply,
			})
			if err != nil {
				return err
			}
			return printOK(*jsonOut, updated.VPN)
		},
	}
	bindListenFlags(editCmd, &editListen)
	editCmd.Flags().String("new-name", "", "Rename VPN")
	editCmd.Flags().String("client-host", "", "Client connect host or IP for share links")
	editCmd.Flags().Bool("clear-client-host", false, "Clear client connect host (use server hostname)")
	editCmd.Flags().Bool("enabled", false, "Enable VPN")
	editCmd.Flags().Bool("disabled", false, "Disable VPN")
	editCmd.Flags().Bool("tls", false, "Enable TLS with self-signed certificate (http only)")
	editCmd.Flags().Bool("no-tls", false, "Disable TLS (http only)")
	editCmd.Flags().Bool("apply", true, "Apply configuration after edit")

	vpn.AddCommand(createCmd, editCmd)
	vpn.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List VPN instances",
		RunE: func(cmd *cobra.Command, args []string) error {
			items, err := orch.ListVPNsFromRequest(cmd.Context(), orchestration.ListVPNsRequest{})
			if err != nil {
				return err
			}
			return printOK(*jsonOut, items.Items)
		},
	})
	vpn.AddCommand(&cobra.Command{
		Use:   "delete [name]",
		Short: "Delete a VPN instance",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := orch.DeleteVPNFromRequest(cmd.Context(), orchestration.DeleteVPNRequest{Name: args[0]})
			return err
		},
	})
	vpn.AddCommand(&cobra.Command{
		Use:   "show [name]",
		Short: "Show VPN details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := orch.GetVPNFromRequest(cmd.Context(), orchestration.GetVPNRequest{Name: args[0]})
			if err != nil {
				return err
			}
			return printOK(*jsonOut, v.VPN)
		},
	})
	return vpn
}

func stringPtrFromFlag(cmd *cobra.Command, name string) *string {
	if !cmd.Flags().Changed(name) {
		return nil
	}
	value, _ := cmd.Flags().GetString(name)
	return &value
}

func intPtrFromFlag(cmd *cobra.Command, name string) *int {
	if !cmd.Flags().Changed(name) {
		return nil
	}
	value, _ := cmd.Flags().GetInt(name)
	return &value
}

func boolPtrFromFlag(cmd *cobra.Command, name string) *bool {
	if !cmd.Flags().Changed(name) {
		return nil
	}
	value, _ := cmd.Flags().GetBool(name)
	return &value
}
