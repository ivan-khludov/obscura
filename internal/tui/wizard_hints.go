package tui

import (
	"github.com/ivan-khludov/obscura/internal/orchestration"
)

const (
	hintVPNName        = "Internal label for this VPN in obscura."
	hintSelectProtocol = "Proxy protocol clients will use to connect."
	hintPort           = "UDP/TCP port sing-box listens on; clients connect here."
	hintClientHost     = "Hostname or IP shown in share links (default: server hostname)."
	hintClientName     = "Label for the first client device (e.g. phone, laptop)."

	hintHTTPTLS       = "Choose whether the HTTP proxy uses TLS."
	hintTLSModePicker = "How the TLS layer is presented to clients and censors."
	hintSNITrojan     = "TLS certificate name (SNI); leave empty to use server hostname."
	hintSNIHy2Tuic    = "TLS certificate name (SNI); QUIC clients verify this name."
	hintRealityHS     = "Real site TLS handshake imitates (e.g. www.bing.com)."
	hintRealityUTLSFP = "Client uTLS fingerprint in share links (fp=); Chrome is most compatible."
	hintEnableTLS     = "Encrypt VMess with TLS; disable only for lab/testing."
	hintShadowTLS     = "Domain whose TLS traffic ShadowTLS imitates on the wire."
	hintTransport     = "How proxy traffic is wrapped before it reaches the server."
	hintTransportPath = "HTTP or WebSocket URL path (e.g. /video)."
	hintGRPCService   = "gRPC service name the tunnel pretends to use."
	hintTransportHost = "Optional Host header for WebSocket or HTTPUpgrade."
	hintFallback      = "Port for decoy non-proxy traffic; 0 disables fallback."
	hintVlessFlow     = "XTLS Vision speeds direct TLS; requires no extra transport."
	hintWGSubnet      = "WireGuard tunnel network in CIDR notation."
	hintWGInterface   = "Userspace is default; system mode uses a kernel TUN device."
	hintWGMTU         = "Maximum packet size through the tunnel; empty keeps default."
	hintHy2Bandwidth  = "Brutal congestion control caps throughput; BBR ignores client limits."
	hintHy2UpMbps     = "Server upload cap for Brutal CC (client must match)."
	hintHy2DownMbps   = "Server download cap for Brutal CC (client must match)."
	hintHy2Obfs       = "Salamander obfuscation hides QUIC traffic patterns."
	hintHy2Masquerade = "Fake HTTP site shown to passive probes on the port."
	hintHy2MasqProxy  = "Backend URL for reverse-proxy masquerade (e.g. local nginx)."
	hintHy2MasqFile   = "Directory served as a static site when probed."
	hintTuicCC        = "QUIC congestion-control algorithm on the server."
	hintTuicZeroRTT   = "0-RTT resumes sessions faster but has replay risk."
)

func (w *wizardState) setPrompt(prompt, hint string) {
	w.prompt = prompt
	w.basePrompt = prompt
	w.promptHint = hint
	w.pickerHints = nil
}

func (w *wizardState) setPickerStep(prompt, hint string, items, itemHints []string) {
	w.prompt = prompt
	w.basePrompt = prompt
	w.promptHint = hint
	w.picker = append([]string{}, items...)
	if len(itemHints) == len(items) {
		w.pickerHints = append([]string{}, itemHints...)
	} else {
		w.pickerHints = nil
	}
}

func (w *wizardState) activeHint() string {
	if w.stepType == stepPicker && w.pickerIdx >= 0 && w.pickerIdx < len(w.pickerHints) && w.pickerHints[w.pickerIdx] != "" {
		return w.pickerHints[w.pickerIdx]
	}
	return w.promptHint
}

func protocolPickerHints(protocols []string) []string {
	hints := make([]string, len(protocols))
	for i, p := range protocols {
		hints[i] = protocolHint(p)
	}
	return hints
}

func protocolHint(name string) string {
	switch name {
	case "http":
		return "HTTP CONNECT proxy; optional TLS."
	case "socks5":
		return "Classic SOCKS5 proxy; TCP and UDP relay."
	case "shadowsocks":
		return "AEAD-encrypted proxy; optional multiplex or ShadowTLS."
	case "trojan":
		return "TLS proxy disguised as HTTPS; many transport modes."
	case "wireguard":
		return "Layer-3 VPN tunnel; needs UDP and TUN on clients."
	case "vmess":
		return "Encrypted proxy over TLS or plain TCP; alter-id legacy."
	case "vless":
		return "Lightweight TLS proxy; supports Reality and XTLS Vision."
	case "hysteria2":
		return "QUIC-based proxy; Brutal CC, obfs, and masquerade."
	case "tuic":
		return "QUIC proxy with UUID auth; low overhead."
	default:
		return "Inbound protocol for client connections."
	}
}

func httpTLSPickerHints() []string {
	return []string{
		"Plain HTTP proxy without encryption.",
		"HTTPS with an auto-generated self-signed certificate.",
	}
}

func vmessTLSPickerHints() []string {
	return []string{
		"Plain TCP without TLS (testing only).",
		"TLS-encrypted VMess (recommended).",
	}
}

func vlessTLSModePickerHints() []string {
	return []string{
		"Use a TLS certificate on this server.",
		"Reality mimics another site's TLS without your cert.",
	}
}

func vlessFlowPickerHints() []string {
	return []string{
		"No special flow; compatible with all transports.",
		"XTLS Vision for direct TLS only; faster than plain TLS.",
	}
}

var realityUTLSFingerprintModes = []string{"Chrome", "Firefox", "Safari", "iOS", "Android", "Edge"}

func realityUTLSFingerprintPickerHints() []string {
	return []string{
		"Most common; best client compatibility.",
		"Firefox TLS fingerprint.",
		"Safari desktop TLS fingerprint.",
		"Safari on iOS TLS fingerprint.",
		"Android TLS fingerprint.",
		"Microsoft Edge TLS fingerprint.",
	}
}

func ssCipherPickerHints() []string {
	methods := orchestration.ShadowsocksMethods()
	hints := make([]string, len(methods))
	for i, m := range methods {
		hints[i] = ssCipherHint(m)
	}
	return hints
}

func ssCipherHint(method string) string {
	switch method {
	case "2022-blake3-aes-128-gcm":
		return "2022 AEAD; 128-bit key (recommended default)."
	case "2022-blake3-aes-256-gcm":
		return "2022 AEAD; 256-bit key."
	case "2022-blake3-chacha20-poly1305":
		return "2022 AEAD; ChaCha20-Poly1305 cipher."
	case "aes-128-gcm":
		return "Legacy AEAD; widely supported."
	case "aes-256-gcm":
		return "Legacy AEAD; stronger key size."
	case "chacha20-ietf-poly1305":
		return "Legacy AEAD; good on devices without AES-NI."
	default:
		return "Shadowsocks encryption method for this VPN."
	}
}

func ssTransportPickerHints() []string {
	return parallelHints(orchestration.ShadowsocksTransportModes(), map[string]string{
		"Direct":              "Single TCP connection per request.",
		"Multiplex":           "Share one connection for many streams.",
		"Multiplex (padding)": "Multiplex with padded frames (harder to fingerprint).",
		"ShadowTLS":           "TLS wrapper that mimics a real HTTPS site.",
	})
}

func inboundTransportPickerHints(protocol string) []string {
	modes := orchestration.InboundTransportModes(protocol)
	return parallelHints(modes, inboundTransportHintMap())
}

func inboundTransportHintMap() map[string]string {
	return map[string]string{
		"Direct":              "TLS over plain TCP (default).",
		"Multiplex":           "Smux over TLS; fewer connections.",
		"Multiplex (padding)": "Smux with padded frames.",
		"WebSocket":           "Tunnel inside a WebSocket (looks like web traffic).",
		"gRPC":                "Tunnel disguised as gRPC over HTTP/2.",
		"HTTP":                "Tunnel over HTTP requests.",
		"HTTPUpgrade":         "HTTP Upgrade to WebSocket-style transport.",
		"QUIC":                "TLS over QUIC/UDP instead of TCP.",
	}
}

func wgInterfacePickerHints() []string {
	return []string{
		"Userspace WireGuard in sing-box (no kernel module).",
		"Kernel TUN interface; needs CAP_NET_ADMIN on the server.",
	}
}

func tuicCongestionPickerHints() []string {
	return []string{
		"Cubic — default QUIC congestion control.",
		"New Reno — classic loss-based algorithm.",
		"BBR — bandwidth-estimation; good on high-latency links.",
	}
}

func tuicZeroRTTPickerHints() []string {
	return []string{
		"Disable 0-RTT; safer against replay (recommended).",
		"Enable 0-RTT; faster reconnects with replay risk.",
	}
}

func hy2BandwidthPickerHints() []string {
	return []string{
		"No Brutal bandwidth limits; client picks its own rate.",
		"Set server up/down caps for Brutal congestion control.",
		"Force BBR on clients; ignore their bandwidth claims.",
	}
}

func hy2ObfsPickerHints() []string {
	return []string{
		"No extra obfuscation beyond QUIC/TLS.",
		"Salamander obfuscation with an auto-generated password.",
	}
}

func hy2MasqueradePickerHints() []string {
	return []string{
		"No masquerade; probes see only QUIC.",
		"Reverse proxy to a real HTTP URL when probed.",
		"Serve static files from a directory when probed.",
	}
}

func parallelHints(items []string, m map[string]string) []string {
	hints := make([]string, len(items))
	for i, item := range items {
		if h, ok := m[item]; ok {
			hints[i] = h
		}
	}
	return hints
}
