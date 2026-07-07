// Package httpproxy implements the HTTP inbound protocol adapter for sing-box.
package httpproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/protocol/auth"
	"github.com/ivan-khludov/obscura/internal/protocol/listen"
)

const typeName = "http"

// Adapter implements protocol.Protocol for sing-box HTTP inbound.
type Adapter struct{}

// Type returns the protocol identifier used in VPN records.
func (a *Adapter) Type() string {
	return typeName
}

// DefaultListen returns default listen options for HTTP inbounds.
func (a *Adapter) DefaultListen() domain.ListenOptions {
	return domain.ListenOptions{
		Listen:     "0.0.0.0",
		ListenPort: 8080,
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

// ProtocolData is the HTTP-specific stored configuration blob.
type ProtocolData struct {
	TLS      bool   `json:"tls,omitempty"`
	CertPath string `json:"cert_path,omitempty"`
	KeyPath  string `json:"key_path,omitempty"`
}

// ParseProtocolData decodes HTTP protocol settings from stored JSON.
func ParseProtocolData(raw []byte) (ProtocolData, error) {
	if len(raw) == 0 {
		return ProtocolData{}, nil
	}
	var data ProtocolData
	if err := json.Unmarshal(raw, &data); err != nil {
		return ProtocolData{}, fmt.Errorf("parse http protocol data: %w", err)
	}
	return data, nil
}

// MarshalProtocolData encodes HTTP protocol-specific settings.
func MarshalProtocolData(data ProtocolData) ([]byte, error) {
	return json.Marshal(data)
}

// ValidateVPN checks VPN and client configuration for HTTP inbounds.
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
	if data.TLS {
		if data.CertPath == "" || data.KeyPath == "" {
			return errors.New("tls requires cert_path and key_path")
		}
	}
	return auth.ValidateEnabledClients(clients, "HTTP proxy", a.ValidateClient)
}

// ValidateClient checks a single client credential set.
func (a *Adapter) ValidateClient(client domain.ClientConfig) error {
	return auth.ValidateClient(client)
}

// RenderInbound builds a sing-box HTTP inbound map from VPN and client state.
func (a *Adapter) RenderInbound(vpn domain.VPNConfig, clients []domain.ClientConfig) (map[string]any, error) {
	if err := a.ValidateVPN(vpn, clients); err != nil {
		return nil, err
	}
	data, err := parseProtocolDataForRender(vpn.ProtocolData)
	if err != nil {
		return nil, err
	}
	inbound := map[string]any{
		"type":        "http",
		"tag":         vpn.Tag,
		"listen":      vpn.Listen.Listen,
		"listen_port": vpn.Listen.ListenPort,
		"users":       listen.UsersFromClients(clients),
	}
	listen.ApplyOptionalFields(inbound, vpn.Listen)
	if data.TLS {
		inbound["tls"] = map[string]any{
			"enabled":          true,
			"certificate_path": data.CertPath,
			"key_path":         data.KeyPath,
		}
	}
	return inbound, nil
}

// ClientURI returns an http(s):// connection URI for the client.
func (a *Adapter) ClientURI(vpn domain.VPNConfig, _ []domain.ClientConfig, client domain.ClientConfig, serverHost string) (string, error) {
	if err := a.ValidateClient(client); err != nil {
		return "", err
	}
	data, err := ParseProtocolData(vpn.ProtocolData)
	if err != nil {
		return "", err
	}
	scheme := "http"
	if data.TLS {
		scheme = "https"
	}
	host := listen.ProxyHost(vpn, serverHost)
	u := &url.URL{
		Scheme: scheme,
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
