package wireguard

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"github.com/ivan-khludov/obscura/internal/domain"
)

var parseProtocolDataHook func([]byte) (ProtocolData, error)

// DefaultAddress is the default server tunnel CIDR for new WireGuard VPNs.
const DefaultAddress = "10.8.0.1/24"

// DefaultMTU is the default WireGuard MTU in sing-box.
const DefaultMTU = 1408

// DefaultAllowedIPs is the default client routing through the tunnel.
var DefaultAllowedIPs = []string{"0.0.0.0/0", "::/0"}

// DefaultPeerKeepalive is the default persistent keepalive interval in seconds.
const DefaultPeerKeepalive = 25

// ProtocolData is the WireGuard-specific stored configuration blob.
type ProtocolData struct {
	System                          bool     `json:"system,omitempty"`
	Name                            string   `json:"name,omitempty"`
	MTU                             int      `json:"mtu,omitempty"`
	Address                         []string `json:"address,omitempty"`
	PrivateKey                      string   `json:"private_key,omitempty"`
	PublicKey                       string   `json:"public_key,omitempty"`
	UDPTimeout                      string   `json:"udp_timeout,omitempty"`
	Workers                         int      `json:"workers,omitempty"`
	PeerPreSharedKey                string   `json:"peer_pre_shared_key,omitempty"`
	PeerPersistentKeepaliveInterval int      `json:"peer_persistent_keepalive_interval,omitempty"`
	PeerReserved                    []int    `json:"peer_reserved,omitempty"`
	Detour                          string   `json:"detour,omitempty"`
	BindInterface                   string   `json:"bind_interface,omitempty"`
	Inet4BindAddress                string   `json:"inet4_bind_address,omitempty"`
	Inet6BindAddress                string   `json:"inet6_bind_address,omitempty"`
	BindAddressNoPort               bool     `json:"bind_address_no_port,omitempty"`
	RoutingMark                     string   `json:"routing_mark,omitempty"`
	ReuseAddr                       bool     `json:"reuse_addr,omitempty"`
	Netns                           string   `json:"netns,omitempty"`
	ConnectTimeout                  string   `json:"connect_timeout,omitempty"`
	TCPFastOpen                     bool     `json:"tcp_fast_open,omitempty"`
	TCPMultiPath                    bool     `json:"tcp_multi_path,omitempty"`
	DisableTCPKeepAlive             bool     `json:"disable_tcp_keep_alive,omitempty"`
	TCPKeepAlive                    string   `json:"tcp_keep_alive,omitempty"`
	TCPKeepAliveInterval            string   `json:"tcp_keep_alive_interval,omitempty"`
	UDPFragment                     bool     `json:"udp_fragment,omitempty"`
	DomainResolver                  string   `json:"domain_resolver,omitempty"`
	NetworkStrategy                 string   `json:"network_strategy,omitempty"`
	NetworkType                     []string `json:"network_type,omitempty"`
	FallbackNetworkType             []string `json:"fallback_network_type,omitempty"`
	FallbackDelay                   string   `json:"fallback_delay,omitempty"`
	ClientAllowedIPs                []string `json:"client_allowed_ips,omitempty"`
}

// ParseProtocolData decodes WireGuard protocol settings from stored JSON.
func ParseProtocolData(raw []byte) (ProtocolData, error) {
	if parseProtocolDataHook != nil {
		return parseProtocolDataHook(raw)
	}
	return parseProtocolData(raw)
}

func parseProtocolData(raw []byte) (ProtocolData, error) {
	if len(raw) == 0 {
		return ProtocolData{}, nil
	}
	var data ProtocolData
	if err := json.Unmarshal(raw, &data); err != nil {
		return ProtocolData{}, fmt.Errorf("parse wireguard protocol data: %w", err)
	}
	return data, nil
}

// MarshalProtocolData encodes WireGuard protocol-specific settings.
func MarshalProtocolData(data ProtocolData) ([]byte, error) {
	return json.Marshal(data)
}

// ValidateOptions checks WireGuard protocol data consistency.
func ValidateOptions(data ProtocolData) error {
	if data.PrivateKey == "" {
		return errors.New("private_key is required for wireguard")
	}
	if len(data.Address) == 0 {
		return errors.New("address is required for wireguard")
	}
	for _, addr := range data.Address {
		if _, _, err := net.ParseCIDR(addr); err != nil {
			return fmt.Errorf("invalid address %q: %w", addr, err)
		}
	}
	if data.MTU != 0 && data.MTU < 1280 {
		return errors.New("mtu must be at least 1280")
	}
	if len(data.PeerReserved) > 0 && len(data.PeerReserved) != 3 {
		return errors.New("peer_reserved must contain exactly 3 bytes")
	}
	if err := ValidateKey(data.PrivateKey); err != nil {
		return fmt.Errorf("private_key: %w", err)
	}
	if data.PublicKey != "" {
		if err := ValidateKey(data.PublicKey); err != nil {
			return fmt.Errorf("public_key: %w", err)
		}
	}
	return nil
}

// ClientAllowedIPs returns allowed_ips for client export.
func ClientAllowedIPs(data ProtocolData) []string {
	if len(data.ClientAllowedIPs) > 0 {
		return append([]string{}, data.ClientAllowedIPs...)
	}
	return append([]string{}, DefaultAllowedIPs...)
}

// ClientTunnelIP assigns a /32 to a client by stable order among enabled clients.
func ClientTunnelIP(data ProtocolData, clients []domain.ClientConfig, clientName string) (string, error) {
	if len(data.Address) == 0 {
		return "", errors.New("address is required")
	}
	hostIP, network, err := net.ParseCIDR(data.Address[0])
	if err != nil {
		return "", err
	}
	serverIP := hostIP.To4()
	if serverIP == nil {
		return "", fmt.Errorf("ipv6 client allocation is not implemented for %s", network.String())
	}
	index := 0
	for _, c := range clients {
		if !c.Enabled {
			continue
		}
		index++
		if c.Name == clientName {
			ip := make(net.IP, len(serverIP))
			copy(ip, serverIP)
			ip[3] = byte(int(ip[3]) + index)
			if !network.Contains(ip) {
				return "", fmt.Errorf("no available address in %s for client %q", network.String(), clientName)
			}
			return ip.String() + "/32", nil
		}
	}
	return "", fmt.Errorf("client %q not found among enabled clients", clientName)
}

// ValidateKey checks base64 WireGuard key length.
func ValidateKey(key string) error {
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return fmt.Errorf("invalid base64 key: %w", err)
	}
	if len(raw) != 32 {
		return fmt.Errorf("wireguard key must be 32 bytes, got %d", len(raw))
	}
	return nil
}
