// Package wireguard implements the WireGuard endpoint protocol adapter for sing-box.
package wireguard

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/listen"
)

const typeName = "wireguard"

// Adapter implements protocol.Protocol for sing-box WireGuard endpoint.
type Adapter struct{}

// Type returns the protocol identifier used in VPN records.
func (a *Adapter) Type() string {
	return typeName
}

// DefaultListen returns default listen options for WireGuard endpoints.
func (a *Adapter) DefaultListen() domain.ListenOptions {
	return domain.ListenOptions{
		Listen:     "0.0.0.0",
		ListenPort: 51820,
	}
}

// SupportedListenFields returns listen field names exposed in advanced configuration.
func (a *Adapter) SupportedListenFields() []string {
	return []string{
		"listen", "listen_port", "bind_interface", "routing_mark", "reuse_addr", "netns",
		"tcp_fast_open", "tcp_multi_path", "disable_tcp_keep_alive", "tcp_keep_alive",
		"tcp_keep_alive_interval", "udp_fragment", "udp_timeout", "detour",
	}
}

// ValidateVPN checks VPN and client configuration for WireGuard endpoints.
func (a *Adapter) ValidateVPN(vpn domain.VPNConfig, clients []domain.ClientConfig) error {
	if vpn.Name == "" {
		return errors.New("vpn name is required")
	}
	if vpn.Tag == "" {
		return errors.New("vpn tag is required")
	}
	if err := listen.ValidateListen(vpn.Listen); err != nil {
		return err
	}
	data, err := ParseProtocolData(vpn.ProtocolData)
	if err != nil {
		return err
	}
	if err := ValidateOptions(data); err != nil {
		return err
	}
	return validateEnabledClients(clients)
}

// ValidateClient checks a single client credential set.
func (a *Adapter) ValidateClient(client domain.ClientConfig) error {
	if client.Password == "" {
		return errors.New("private key is required")
	}
	if client.Username == "" {
		return errors.New("public key is required")
	}
	if err := ValidateKey(client.Password); err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	if err := ValidateKey(client.Username); err != nil {
		return fmt.Errorf("public key: %w", err)
	}
	pub, err := PublicKeyFromPrivate(client.Password)
	if err != nil {
		return err
	}
	if pub != client.Username {
		return errors.New("public key does not match private key")
	}
	return nil
}

// validateEnabledClients validates protocol options or configuration consistency.
func validateEnabledClients(clients []domain.ClientConfig) error {
	enabled := 0
	for _, c := range clients {
		if !c.Enabled {
			continue
		}
		if err := (&Adapter{}).ValidateClient(c); err != nil {
			return fmt.Errorf("client %q: %w", c.Name, err)
		}
		enabled++
	}
	if enabled == 0 {
		return errors.New("at least one enabled client is required for WireGuard")
	}
	return nil
}

// RenderInbound is not used; WireGuard renders as an endpoint.
func (a *Adapter) RenderInbound(_ domain.VPNConfig, _ []domain.ClientConfig) (map[string]any, error) {
	return nil, errors.New("wireguard does not use inbounds")
}

// RenderEndpoints builds sing-box WireGuard endpoint maps from VPN and client state.
func (a *Adapter) RenderEndpoints(vpn domain.VPNConfig, clients []domain.ClientConfig) ([]map[string]any, error) {
	if err := a.ValidateVPN(vpn, clients); err != nil {
		return nil, err
	}
	data, err := ParseProtocolData(vpn.ProtocolData)
	if err != nil {
		return nil, err
	}
	endpoint, err := renderEndpoint(vpn, data, clients)
	if err != nil {
		return nil, err
	}
	return []map[string]any{endpoint}, nil
}

// ClientURI returns a wireguard:// connection URI for the client.
func (a *Adapter) ClientURI(vpn domain.VPNConfig, clients []domain.ClientConfig, client domain.ClientConfig, serverHost string) (string, error) {
	if err := a.ValidateClient(client); err != nil {
		return "", err
	}
	data, err := ParseProtocolData(vpn.ProtocolData)
	if err != nil {
		return "", err
	}
	clientAddress, err := ClientTunnelIP(data, clients, client.Name)
	if err != nil {
		return "", err
	}
	host := listen.ProxyHost(vpn, serverHost)
	q := url.Values{}
	q.Set("publickey", data.PublicKey)
	q.Set("address", clientAddress)
	q.Set("allowedips", strings.Join(ClientAllowedIPs(data), ","))
	if data.PeerPreSharedKey != "" {
		q.Set("presharedkey", data.PeerPreSharedKey)
	}
	keepalive := data.PeerPersistentKeepaliveInterval
	if keepalive == 0 {
		keepalive = DefaultPeerKeepalive
	}
	q.Set("keepalive", strconv.Itoa(keepalive))
	mtu := data.MTU
	if mtu == 0 {
		mtu = DefaultMTU
	}
	q.Set("mtu", strconv.Itoa(mtu))
	u := &url.URL{
		Scheme:   "wireguard",
		User:     url.User(client.Password),
		Host:     net.JoinHostPort(host, strconv.Itoa(vpn.Listen.ListenPort)),
		RawQuery: q.Encode(),
	}
	if client.Name != "" {
		u.Fragment = client.Name
	}
	return u.String(), nil
}

// ClientQRContent returns the WireGuard .conf file content for QR encoding.
func (a *Adapter) ClientQRContent(vpn domain.VPNConfig, clients []domain.ClientConfig, client domain.ClientConfig, serverHost string) (string, error) {
	if err := a.ValidateClient(client); err != nil {
		return "", err
	}
	data, err := ParseProtocolData(vpn.ProtocolData)
	if err != nil {
		return "", err
	}
	clientAddress, err := ClientTunnelIP(data, clients, client.Name)
	if err != nil {
		return "", err
	}
	return RenderClientConf(vpn, data, client, serverHost, clientAddress), nil
}

// RouteExtensions returns route rules for WireGuard endpoint traffic.
func (a *Adapter) RouteExtensions(vpn domain.VPNConfig) ([]map[string]any, error) {
	return []map[string]any{{"inbound": vpn.Tag, "outbound": "direct"}}, nil
}

// AdditionalInbounds returns extra sing-box inbounds for the VPN protocol.
func (a *Adapter) AdditionalInbounds(_ domain.VPNConfig, _ []domain.ClientConfig) ([]map[string]any, error) {
	return nil, nil
}

// UsesInbound reports whether the protocol renders a sing-box inbound.
func (a *Adapter) UsesInbound() bool { return false }

// FirewallProtos returns firewall protocols to open for the VPN listen port.
func (a *Adapter) FirewallProtos() []string { return []string{"udp"} }
