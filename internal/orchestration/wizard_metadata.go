package orchestration

import (
	"strings"

	"github.com/ivan-khludov/obscura/internal/protocol/httpproxy"
	"github.com/ivan-khludov/obscura/internal/protocol/shadowsocks"
	"github.com/ivan-khludov/obscura/internal/protocol/trojan"
	"github.com/ivan-khludov/obscura/internal/protocol/tuic"
	"github.com/ivan-khludov/obscura/internal/protocol/vless"
	"github.com/ivan-khludov/obscura/internal/protocol/vmess"
	"github.com/ivan-khludov/obscura/internal/protocol/wireguard"
)

// ShadowsocksMethods returns supported SS cipher methods for picker.
func ShadowsocksMethods() []string {
	return append([]string{}, shadowsocks.Methods...)
}

// DefaultShadowsocksMethod returns default Shadowsocks cipher method.
func DefaultShadowsocksMethod() string {
	return shadowsocks.DefaultMethod
}

// ShadowsocksTransportModes returns Shadowsocks transport picker modes.
func ShadowsocksTransportModes() []string {
	return append([]string{}, shadowsocks.TransportModes...)
}

// DefaultShadowsocksHandshake returns default ShadowTLS handshake host.
func DefaultShadowsocksHandshake() string {
	return shadowsocks.DefaultShadowTLSHandshake
}

// InboundTransportModes returns inbound transport modes for protocol.
func InboundTransportModes(protocolName string) []string {
	switch protocolName {
	case "vmess":
		return append([]string{}, vmess.TransportModes...)
	case "vless":
		return append([]string{}, vless.TransportModes...)
	default:
		return append([]string{}, trojan.TransportModes...)
	}
}

// VLESSFlowModes returns VLESS flow picker modes.
func VLESSFlowModes() []string {
	return append([]string{}, vless.FlowModes...)
}

// VLESSFlowByIndex converts picker index to canonical VLESS flow value.
func VLESSFlowByIndex(idx int) string {
	modes := vless.FlowModes
	if idx < 0 || idx >= len(modes) {
		return ""
	}
	if modes[idx] == "XTLS Vision" {
		return vless.FlowVision
	}
	return ""
}

// VLESSFlowVision returns canonical VLESS vision flow value.
func VLESSFlowVision() string {
	return vless.FlowVision
}

// WireguardDefaults returns default subnet and MTU for WireGuard.
func WireguardDefaults() (address string, mtu int) {
	return wireguard.DefaultAddress, wireguard.DefaultMTU
}

// TUICCongestionPickerModes returns display labels for TUIC congestion picker.
func TUICCongestionPickerModes() []string {
	return []string{"Cubic", "New Reno", "BBR"}
}

// TUICCongestionByIndex converts picker index to TUIC wire value.
func TUICCongestionByIndex(idx int) string {
	switch idx {
	case 0:
		return tuic.CongestionCubic
	case 1:
		return tuic.CongestionNewReno
	case 2:
		return tuic.CongestionBBR
	default:
		return tuic.CongestionCubic
	}
}

// HTTPTLSEnabledFromVPN extracts HTTP TLS toggle from VPN protocol data.
func HTTPTLSEnabledFromVPN(vpn VPNView) bool {
	if strings.ToLower(vpn.Protocol) != "http" {
		return false
	}
	data, err := httpproxy.ParseProtocolData(vpn.ProtocolData)
	if err != nil {
		return false
	}
	return data.TLS
}
