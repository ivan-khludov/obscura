package tui

import (
	"context"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/orchestration"
)

// buildVmessCreateInput assembles protocol or input data from create parameters.
func buildVmessCreateInput(w wizardState) orchestration.VMessCreateOptions {
	t := buildTrojanCreateInput(w)
	return orchestration.BuildVMessCreateOptionsFromFields(w.vmessNoTLS, t)
}

// buildTUICCreateInput assembles protocol or input data from create parameters.
func buildTUICCreateInput(w wizardState) orchestration.TUICCreateOptions {
	return orchestration.BuildTUICCreateOptions(w.tuicServerName, w.tuicCongestionControl, w.tuicZeroRTT)
}

// buildHysteria2CreateInput assembles protocol or input data from create parameters.
func buildHysteria2CreateInput(w wizardState) orchestration.Hysteria2CreateOptions {
	return orchestration.BuildHysteria2CreateOptions(
		w.hy2ServerName,
		w.hy2UpMbps,
		w.hy2DownMbps,
		w.hy2IgnoreBW,
		w.hy2ObfsPassword,
		w.hy2MasqueradeURL,
	)
}

// buildVlessCreateInput assembles protocol or input data from create parameters.
func buildVlessCreateInput(w wizardState) orchestration.VLESSCreateOptions {
	t := buildTrojanCreateInput(w)
	return orchestration.BuildVLESSCreateOptionsFromFields(w.vlessFlow, w.vlessReality, w.realityUTLSFingerprint, t)
}

// buildTrojanCreateInput assembles protocol or input data from create parameters.
func buildTrojanCreateInput(w wizardState) orchestration.TrojanCreateOptions {
	return orchestration.BuildTrojanCreateOptionsFromFields(
		w.trojanServerName,
		w.trojanTransport,
		w.trojanTransportPath,
		w.trojanTransportHost,
		w.trojanTransportServiceName,
		w.trojanMultiplex,
		w.trojanMultiplexPadding,
		w.trojanFallbackPort,
	)
}

// buildCreateVPNRequest assembles request-first create data from wizard state.
func buildCreateVPNRequest(w wizardState) orchestration.CreateVPNRequest {
	req := orchestration.CreateVPNRequest{
		Name:                 w.vpnName,
		Protocol:             w.protocol,
		ClientHost:           w.clientHost,
		Enabled:              true,
		Listen:               domain.ListenOptions{Listen: "0.0.0.0", ListenPort: w.listenPort},
		InitialClientName:    w.clientName,
		HTTPTLS:              w.httpTLS,
		SSMethod:             w.ssMethod,
		SSPlugin:             w.ssPlugin,
		SSPluginOpts:         w.ssPluginOpts,
		SSMultiplex:          w.ssMultiplex,
		SSMultiplexPadding:   w.ssMultiplexPadding,
		SSShadowTLS:          w.ssShadowTLS,
		SSShadowTLSHandshake: w.ssShadowTLSHandshake,
		HTTP:                 orchestration.HTTPCreateOptions{TLS: w.httpTLS},
		Shadowsocks: orchestration.BuildShadowsocksCreateOptions(
			w.ssMethod,
			w.ssPlugin,
			w.ssPluginOpts,
			w.ssMultiplex,
			w.ssMultiplexPadding,
			w.ssShadowTLS,
			w.ssShadowTLSHandshake,
			0,
			false,
			w.listenPort,
		),
		Trojan:    buildTrojanCreateInput(w),
		VMess:     buildVmessCreateInput(w),
		VLESS:     buildVlessCreateInput(w),
		Hysteria2: buildHysteria2CreateInput(w),
		TUIC:      buildTUICCreateInput(w),
	}
	if w.protocol == "wireguard" {
		req.Wireguard = buildWireguardCreateInput(w)
	}
	return req
}

// createVPNCmd returns a Bubble Tea command for async work.
func createVPNCmd(orch *orchestration.Facade, req orchestration.CreateVPNRequest) tea.Cmd {
	return func() tea.Msg {
		result, err := orch.CreateVPNFromRequest(context.Background(), req)
		if err != nil {
			return createVPNResultMsg{err: err}
		}
		if result.URI != "" && result.Client != nil {
			header := fmt.Sprintf("Created VPN %q on port %d\n\n", result.VPN.Name, result.VPN.Listen.ListenPort)
			text := header + result.URI
			if export, err := orch.ShowClientFromRequest(context.Background(), orchestration.ShowClientRequest{
				VPNName:         result.VPN.Name,
				Name:            result.Client.Name,
				IncludeQR:       true,
				AllowQRFallback: true,
			}); err == nil {
				if uriBlock, _ := formatClientExport(result.URI, export.QRContent); uriBlock != "" {
					text = header + uriBlock
				}
			}
			return createVPNResultMsg{text: text}
		}
		return createVPNResultMsg{text: fmt.Sprintf("Created VPN %q on port %d", result.VPN.Name, result.VPN.Listen.ListenPort)}
	}
}

// buildWireguardCreateInput assembles protocol or input data from create parameters.
func buildWireguardCreateInput(w wizardState) orchestration.WireguardCreateOptions {
	return orchestration.BuildWireguardCreateOptions(w.wgSystem, w.wgAddress, w.wgMTU)
}
