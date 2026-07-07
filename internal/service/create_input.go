package service

import "github.com/google/go-cmp/cmp"

// NormalizeCreateVPNInput merges compatibility fields into canonical per-protocol
// create options and applies protocol defaults.
func NormalizeCreateVPNInput(in CreateVPNInput) CreateVPNInput {
	if in.Protocol == "" {
		in.Protocol = "socks5"
	}
	if in.Listen.ListenPort == 0 {
		switch in.Protocol {
		case "http":
			in.Listen.ListenPort = 8080
		case "shadowsocks":
			in.Listen.ListenPort = 8388
		case "wireguard":
			in.Listen.ListenPort = 51820
		case "trojan", "vmess", "vless", "hysteria2", "tuic":
			in.Listen.ListenPort = 443
		default:
			in.Listen.ListenPort = 1080
		}
	}
	if in.Protocol == "http" && !hasHTTPOptions(in.HTTP) {
		in.HTTP = HTTPCreateOptions{TLS: in.HTTPTLS}
	}
	if in.Protocol == "shadowsocks" && !hasShadowsocksOptions(in.Shadowsocks) {
		in.Shadowsocks = ShadowsocksCreateOptions{
			Method:                 in.SSMethod,
			Plugin:                 in.SSPlugin,
			PluginOpts:             in.SSPluginOpts,
			Multiplex:              in.SSMultiplex,
			MultiplexPadding:       in.SSMultiplexPadding,
			ShadowTLS:              in.SSShadowTLS,
			ShadowTLSHandshake:     in.SSShadowTLSHandshake,
			ShadowTLSHandshakePort: in.SSShadowTLSHandshakePort,
			ShadowTLSStrictMode:    in.SSShadowTLSStrictMode,
			ListenPort:             in.Listen.ListenPort,
		}
	}
	return in
}

func hasHTTPOptions(v HTTPCreateOptions) bool {
	return !cmp.Equal(v, HTTPCreateOptions{})
}

func hasShadowsocksOptions(v ShadowsocksCreateOptions) bool {
	return !cmp.Equal(v, ShadowsocksCreateOptions{})
}
