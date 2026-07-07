// Package shadowsocks implements the Shadowsocks SS-2022 inbound adapter for sing-box.
package shadowsocks

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/protocol/auth"
	"github.com/ivan-khludov/obscura/internal/protocol/listen"
)

const typeName = "shadowsocks"

const internalListen = "127.0.0.1"

var parseProtocolData = ParseProtocolData

// Adapter implements protocol.Protocol for sing-box Shadowsocks inbound.
type Adapter struct{}

// Type returns the protocol identifier used in VPN records.
func (a *Adapter) Type() string {
	return typeName
}

// DefaultListen returns default listen options for Shadowsocks inbounds.
func (a *Adapter) DefaultListen() domain.ListenOptions {
	return domain.ListenOptions{
		Listen:     "0.0.0.0",
		ListenPort: 8388,
	}
}

// SupportedListenFields returns listen field names exposed in advanced configuration.
func (a *Adapter) SupportedListenFields() []string {
	return []string{
		"listen", "listen_port", "bind_interface", "routing_mark", "reuse_addr", "netns",
		"tcp_fast_open", "tcp_multi_path", "disable_tcp_keep_alive", "tcp_keep_alive",
		"tcp_keep_alive_interval", "udp_fragment", "udp_timeout", "detour", "network",
	}
}

// ProtocolData is the Shadowsocks-specific stored configuration blob.
type ProtocolData struct {
	Method                 string `json:"method"`
	ServerPassword         string `json:"server_password"`
	Plugin                 string `json:"plugin,omitempty"`
	PluginOpts             string `json:"plugin_opts,omitempty"`
	Multiplex              bool   `json:"multiplex,omitempty"`
	MultiplexPadding       bool   `json:"multiplex_padding,omitempty"`
	ShadowTLS              bool   `json:"shadowtls,omitempty"`
	ShadowTLSVersion       int    `json:"shadowtls_version,omitempty"`
	ShadowTLSPassword      string `json:"shadowtls_password,omitempty"`
	ShadowTLSBackendPort   int    `json:"shadowtls_backend_port,omitempty"`
	ShadowTLSHandshake     string `json:"shadowtls_handshake,omitempty"`
	ShadowTLSHandshakePort int    `json:"shadowtls_handshake_port,omitempty"`
	ShadowTLSStrictMode    bool   `json:"shadowtls_strict_mode,omitempty"`
}

// ParseProtocolData decodes Shadowsocks protocol settings from stored JSON.
func ParseProtocolData(raw []byte) (ProtocolData, error) {
	if len(raw) == 0 {
		return ProtocolData{}, nil
	}
	var data ProtocolData
	if err := json.Unmarshal(raw, &data); err != nil {
		return ProtocolData{}, fmt.Errorf("parse shadowsocks protocol data: %w", err)
	}
	return data, nil
}

// MarshalProtocolData encodes Shadowsocks protocol-specific settings.
func MarshalProtocolData(data ProtocolData) ([]byte, error) {
	return json.Marshal(data)
}

// ValidateVPN checks VPN and client configuration for Shadowsocks inbounds.
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
	if data.Method == "" {
		return errors.New("shadowsocks method is required")
	}
	if !SupportsMultiUser(data.Method) {
		return fmt.Errorf("method %q does not support multi-user in sing-box; use 2022-blake3-aes-128-gcm or 2022-blake3-aes-256-gcm", data.Method)
	}
	if err := ValidateKey(data.Method, data.ServerPassword); err != nil {
		return fmt.Errorf("server_password: %w", err)
	}
	if err := ValidateOptions(data); err != nil {
		return err
	}
	if data.ShadowTLS && data.ShadowTLSBackendPort != 0 && data.ShadowTLSBackendPort == vpn.Listen.ListenPort {
		return fmt.Errorf("shadowtls backend port must differ from public listen port %d", vpn.Listen.ListenPort)
	}
	return auth.ValidateEnabledClients(clients, "Shadowsocks", func(c domain.ClientConfig) error {
		if err := a.ValidateClient(c); err != nil {
			return err
		}
		return ValidateKey(data.Method, c.Password)
	})
}

// ValidateClient checks a single client credential set.
func (a *Adapter) ValidateClient(client domain.ClientConfig) error {
	if client.Name == "" {
		return errors.New("client name is required")
	}
	if client.Password == "" {
		return errors.New("password is required")
	}
	return nil
}

// UsersFromClients builds sing-box Shadowsocks user entries from enabled clients.
func UsersFromClients(clients []domain.ClientConfig) []map[string]string {
	users := make([]map[string]string, 0)
	for _, c := range clients {
		if !c.Enabled {
			continue
		}
		users = append(users, map[string]string{
			"name":     c.Name,
			"password": c.Password,
		})
	}
	return users
}

// RenderInbound builds a sing-box Shadowsocks inbound map from VPN and client state.
func (a *Adapter) RenderInbound(vpn domain.VPNConfig, clients []domain.ClientConfig) (map[string]any, error) {
	if err := a.ValidateVPN(vpn, clients); err != nil {
		return nil, err
	}
	data, err := parseProtocolData(vpn.ProtocolData)
	if err != nil {
		return nil, err
	}
	listenAddr := vpn.Listen.Listen
	if data.ShadowTLS {
		listenAddr = internalListen
	}
	inbound := map[string]any{
		"type":        "shadowsocks",
		"tag":         vpn.Tag,
		"listen":      listenAddr,
		"listen_port": vpn.Listen.ListenPort,
		"method":      data.Method,
		"password":    data.ServerPassword,
		"users":       UsersFromClients(clients),
	}
	if data.ShadowTLS {
		inbound["network"] = "tcp"
		inbound["listen_port"] = shadowTLSBackendPort(data, vpn.Listen.ListenPort)
	}
	applyMultiplex(inbound, data)
	listen.ApplyOptionalFields(inbound, vpn.Listen)
	if data.ShadowTLS {
		inbound["listen"] = internalListen
	}
	return inbound, nil
}

// AdditionalInbounds renders companion inbounds such as ShadowTLS frontends.
func (a *Adapter) AdditionalInbounds(vpn domain.VPNConfig, clients []domain.ClientConfig) ([]map[string]any, error) {
	data, err := ParseProtocolData(vpn.ProtocolData)
	if err != nil {
		return nil, err
	}
	if !data.ShadowTLS {
		return nil, nil
	}
	if err := a.ValidateVPN(vpn, clients); err != nil {
		return nil, err
	}
	inbound := map[string]any{
		"type":        "shadowtls",
		"tag":         vpn.Tag + "-st",
		"listen":      vpn.Listen.Listen,
		"listen_port": vpn.Listen.ListenPort,
		"version":     shadowTLSVersion(data),
		"users":       shadowTLSUsers(clients, data.ShadowTLSPassword),
		"handshake": map[string]any{
			"server":      data.ShadowTLSHandshake,
			"server_port": shadowTLSHandshakePort(data),
		},
		"detour": vpn.Tag,
	}
	if data.ShadowTLSStrictMode {
		inbound["strict_mode"] = true
	}
	listen.ApplyOptionalFields(inbound, vpn.Listen)
	return []map[string]any{inbound}, nil
}

// ClientURI returns a SIP002 ss:// connection URI for the client.
func (a *Adapter) ClientURI(vpn domain.VPNConfig, _ []domain.ClientConfig, client domain.ClientConfig, serverHost string) (string, error) {
	if err := a.ValidateClient(client); err != nil {
		return "", err
	}
	data, err := ParseProtocolData(vpn.ProtocolData)
	if err != nil {
		return "", err
	}
	if err := ValidateKey(data.Method, client.Password); err != nil {
		return "", err
	}
	host := listen.ProxyHost(vpn, serverHost)
	userinfo := base64.RawURLEncoding.EncodeToString([]byte(data.Method + ":" + client.Password))
	u := &url.URL{
		Scheme: "ss",
		User:   url.User(userinfo),
		Host:   fmt.Sprintf("%s:%d", host, vpn.Listen.ListenPort),
	}
	if data.Plugin != "" {
		q := u.Query()
		q.Set("plugin", data.Plugin)
		q.Set("plugin-opts", data.PluginOpts)
		u.RawQuery = q.Encode()
	}
	return u.String(), nil
}

// RouteExtensions returns optional route rules for the VPN protocol.
func (a *Adapter) RouteExtensions(_ domain.VPNConfig) ([]map[string]any, error) {
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
