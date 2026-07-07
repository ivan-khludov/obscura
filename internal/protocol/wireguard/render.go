package wireguard

import (
	"strconv"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/listen"
)

// renderEndpoint renders sing-box configuration fragments for the protocol.
func renderEndpoint(vpn domain.VPNConfig, data ProtocolData, clients []domain.ClientConfig) (map[string]any, error) {
	endpoint := map[string]any{
		"type":        "wireguard",
		"tag":         vpn.Tag,
		"system":      data.System,
		"address":     append([]string{}, data.Address...),
		"private_key": data.PrivateKey,
		"listen_port": vpn.Listen.ListenPort,
	}
	if data.Name != "" {
		endpoint["name"] = data.Name
	}
	mtu := data.MTU
	if mtu == 0 {
		mtu = DefaultMTU
	}
	endpoint["mtu"] = mtu
	if data.UDPTimeout != "" {
		endpoint["udp_timeout"] = data.UDPTimeout
	}
	if data.Workers > 0 {
		endpoint["workers"] = data.Workers
	}
	applyDialFields(endpoint, data)
	listen.ApplyOptionalFields(endpoint, vpn.Listen)
	peers, err := renderPeers(data, clients)
	if err != nil {
		return nil, err
	}
	endpoint["peers"] = peers
	return endpoint, nil
}

// renderPeers renders sing-box configuration fragments for the protocol.
func renderPeers(data ProtocolData, clients []domain.ClientConfig) ([]map[string]any, error) {
	peers := make([]map[string]any, 0)
	for _, c := range clients {
		if !c.Enabled {
			continue
		}
		if c.Username == "" {
			return nil, errClientPublicKey(c.Name)
		}
		allowedIP, err := ClientTunnelIP(data, clients, c.Name)
		if err != nil {
			return nil, err
		}
		peer := map[string]any{
			"public_key":  c.Username,
			"allowed_ips": []string{allowedIP},
		}
		if data.PeerPreSharedKey != "" {
			peer["pre_shared_key"] = data.PeerPreSharedKey
		}
		keepalive := data.PeerPersistentKeepaliveInterval
		if keepalive == 0 {
			keepalive = DefaultPeerKeepalive
		}
		peer["persistent_keepalive_interval"] = keepalive
		if len(data.PeerReserved) == 3 {
			peer["reserved"] = data.PeerReserved
		}
		peers = append(peers, peer)
	}
	return peers, nil
}

// applyDialFields applies transport, TLS preview, or option fields to protocol data.
func applyDialFields(endpoint map[string]any, data ProtocolData) {
	if data.Detour != "" {
		endpoint["detour"] = data.Detour
	}
	if data.BindInterface != "" {
		endpoint["bind_interface"] = data.BindInterface
	}
	if data.Inet4BindAddress != "" {
		endpoint["inet4_bind_address"] = data.Inet4BindAddress
	}
	if data.Inet6BindAddress != "" {
		endpoint["inet6_bind_address"] = data.Inet6BindAddress
	}
	if data.BindAddressNoPort {
		endpoint["bind_address_no_port"] = true
	}
	if data.RoutingMark != "" {
		endpoint["routing_mark"] = data.RoutingMark
	}
	if data.ReuseAddr {
		endpoint["reuse_addr"] = true
	}
	if data.Netns != "" {
		endpoint["netns"] = data.Netns
	}
	if data.ConnectTimeout != "" {
		endpoint["connect_timeout"] = data.ConnectTimeout
	}
	if data.TCPFastOpen {
		endpoint["tcp_fast_open"] = true
	}
	if data.TCPMultiPath {
		endpoint["tcp_multi_path"] = true
	}
	if data.DisableTCPKeepAlive {
		endpoint["disable_tcp_keep_alive"] = true
	}
	if data.TCPKeepAlive != "" {
		endpoint["tcp_keep_alive"] = data.TCPKeepAlive
	}
	if data.TCPKeepAliveInterval != "" {
		endpoint["tcp_keep_alive_interval"] = data.TCPKeepAliveInterval
	}
	if data.UDPFragment {
		endpoint["udp_fragment"] = true
	}
	if data.DomainResolver != "" {
		endpoint["domain_resolver"] = data.DomainResolver
	}
	if data.NetworkStrategy != "" {
		endpoint["network_strategy"] = data.NetworkStrategy
	}
	if len(data.NetworkType) > 0 {
		endpoint["network_type"] = append([]string{}, data.NetworkType...)
	}
	if len(data.FallbackNetworkType) > 0 {
		endpoint["fallback_network_type"] = append([]string{}, data.FallbackNetworkType...)
	}
	if data.FallbackDelay != "" {
		endpoint["fallback_delay"] = data.FallbackDelay
	}
}

// errClientPublicKey performs an internal helper operation.
func errClientPublicKey(name string) error {
	return &clientKeyError{name: name}
}

type clientKeyError struct{ name string }

// Error implements the error interface for clientKeyError.
func (e *clientKeyError) Error() string {
	return "client " + strconv.Quote(e.name) + ": public key (username) is required"
}
