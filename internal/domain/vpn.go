package domain

import "time"

// ProtocolType is the stable identifier for a supported VPN protocol.
type ProtocolType string

// Supported VPN protocol identifiers.
const (
	ProtocolHTTP        ProtocolType = "http"
	ProtocolSOCKS5      ProtocolType = "socks5"
	ProtocolShadowsocks ProtocolType = "shadowsocks"
	ProtocolTrojan      ProtocolType = "trojan"
	ProtocolWireGuard   ProtocolType = "wireguard"
	ProtocolVMess       ProtocolType = "vmess"
	ProtocolVLESS       ProtocolType = "vless"
	ProtocolHysteria2   ProtocolType = "hysteria2"
	ProtocolTUIC        ProtocolType = "tuic"
)

// VPN represents a logical VPN instance backed by a sing-box inbound.
type VPN struct {
	ID           int64
	Name         string
	Protocol     string
	Tag          string
	Enabled      bool
	ClientHost   string
	Listen       ListenOptions
	ProtocolData []byte
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// VPNConfig is the input shape used by protocol adapters during validation and rendering.
type VPNConfig struct {
	Name         string
	Protocol     string
	Tag          string
	Enabled      bool
	ClientHost   string
	Listen       ListenOptions
	ProtocolData []byte
}

// CreateVPNSpec is the protocol-neutral command shape for creating a VPN.
type CreateVPNSpec struct {
	Name              string
	Protocol          ProtocolType
	ClientHost        string
	Listen            ListenOptions
	Enabled           bool
	InitialClientName string
	ProtocolOptions   any
}
