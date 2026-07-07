// Package socks5 implements the SOCKS5 inbound protocol adapter for sing-box.
package socks5

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/protocol/auth"
	"github.com/ivan-khludov/obscura/internal/protocol/listen"
)

// typeName is the protocol registry identifier for SOCKS5.
const typeName = "socks5"

// Adapter implements protocol.Protocol for sing-box SOCKS inbound.
type Adapter struct{}

// Type returns the protocol identifier used in VPN records.
func (a *Adapter) Type() string {
	return typeName
}

// DefaultListen returns default listen options for SOCKS5 inbounds.
func (a *Adapter) DefaultListen() domain.ListenOptions {
	return domain.DefaultListenOptions()
}

// SupportedListenFields returns listen field names exposed in advanced configuration.
func (a *Adapter) SupportedListenFields() []string {
	return []string{
		"listen", "listen_port", "bind_interface", "routing_mark", "reuse_addr", "netns",
		"tcp_fast_open", "tcp_multi_path", "disable_tcp_keep_alive", "tcp_keep_alive",
		"tcp_keep_alive_interval", "udp_fragment", "udp_timeout", "detour",
	}
}

// ValidateVPN checks VPN and client configuration for SOCKS5 inbounds.
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
	return auth.ValidateEnabledClients(clients, "SOCKS5", a.ValidateClient)
}

// ValidateClient checks a single client credential set.
func (a *Adapter) ValidateClient(client domain.ClientConfig) error {
	return auth.ValidateClient(client)
}

// RenderInbound builds a sing-box SOCKS inbound map from VPN and client state.
func (a *Adapter) RenderInbound(vpn domain.VPNConfig, clients []domain.ClientConfig) (map[string]any, error) {
	if err := a.ValidateVPN(vpn, clients); err != nil {
		return nil, err
	}
	inbound := map[string]any{
		"type":        "socks",
		"tag":         vpn.Tag,
		"listen":      vpn.Listen.Listen,
		"listen_port": vpn.Listen.ListenPort,
		"users":       listen.UsersFromClients(clients),
	}
	listen.ApplyOptionalFields(inbound, vpn.Listen)
	return inbound, nil
}

// ClientURI returns a socks5:// connection URI for the client.
func (a *Adapter) ClientURI(vpn domain.VPNConfig, _ []domain.ClientConfig, client domain.ClientConfig, serverHost string) (string, error) {
	if err := a.ValidateClient(client); err != nil {
		return "", err
	}
	host := listen.ProxyHost(vpn, serverHost)
	u := &url.URL{
		Scheme: "socks5",
		Host:   net.JoinHostPort(host, strconv.Itoa(vpn.Listen.ListenPort)),
		User:   url.UserPassword(client.Username, client.Password),
	}
	return u.String(), nil
}

// RouteExtensions returns optional route rules for the VPN protocol.
func (a *Adapter) RouteExtensions(_ domain.VPNConfig) ([]map[string]any, error) {
	return nil, nil
}

// AdditionalInbounds returns extra sing-box inbounds for the VPN protocol.
func (a *Adapter) AdditionalInbounds(_ domain.VPNConfig, _ []domain.ClientConfig) ([]map[string]any, error) {
	return nil, nil
}

// RenderEndpoints returns sing-box endpoints for the VPN protocol.
func (a *Adapter) RenderEndpoints(_ domain.VPNConfig, _ []domain.ClientConfig) ([]map[string]any, error) {
	return nil, nil
}

// ClientQRContent returns QR payload for the client connection.
func (a *Adapter) ClientQRContent(vpn domain.VPNConfig, clients []domain.ClientConfig, client domain.ClientConfig, serverHost string) (string, error) {
	return protocol.ClientQRFromURI(a, vpn, clients, client, serverHost)
}

// UsesInbound reports whether the protocol renders a sing-box inbound.
func (a *Adapter) UsesInbound() bool { return true }

// FirewallProtos returns firewall protocols to open for the VPN listen port.
func (a *Adapter) FirewallProtos() []string { return protocol.DefaultFirewallProtos }

// ProtocolData is the SOCKS5-specific stored configuration blob.
type ProtocolData struct{}

// MarshalProtocolData encodes SOCKS5 protocol-specific settings.
func MarshalProtocolData(data ProtocolData) ([]byte, error) {
	return json.Marshal(data)
}
