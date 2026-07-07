// Package tuic implements the TUIC inbound protocol adapter for sing-box.
package tuic

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/protocol/listen"
)

const typeName = "tuic"

var parseProtocolData = ParseProtocolData

// Adapter implements protocol.Protocol for sing-box TUIC inbound.
type Adapter struct{}

// Type returns the protocol identifier used in VPN records.
func (a *Adapter) Type() string {
	return typeName
}

// DefaultListen returns default listen options for TUIC inbounds.
func (a *Adapter) DefaultListen() domain.ListenOptions {
	return domain.ListenOptions{
		Listen:     "0.0.0.0",
		ListenPort: 443,
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

// ValidateVPN checks VPN and client configuration for TUIC inbounds.
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
	data, err := parseProtocolData(vpn.ProtocolData)
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
	if client.Username == "" {
		return errors.New("uuid is required")
	}
	if _, err := uuid.Parse(client.Username); err != nil {
		return fmt.Errorf("invalid uuid: %w", err)
	}
	if client.Password == "" {
		return errors.New("password is required")
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
		return errors.New("at least one enabled client is required for TUIC authentication")
	}
	return nil
}

// RenderInbound builds a sing-box TUIC inbound map from VPN and client state.
func (a *Adapter) RenderInbound(vpn domain.VPNConfig, clients []domain.ClientConfig) (map[string]any, error) {
	if err := a.ValidateVPN(vpn, clients); err != nil {
		return nil, err
	}
	data, err := parseProtocolData(vpn.ProtocolData)
	if err != nil {
		return nil, err
	}
	inbound := map[string]any{
		"type":        "tuic",
		"tag":         vpn.Tag,
		"listen":      vpn.Listen.Listen,
		"listen_port": vpn.Listen.ListenPort,
		"users":       UsersFromClients(clients),
		"tls":         renderTLS(data),
	}
	listen.ApplyOptionalFields(inbound, vpn.Listen)
	cc := data.CongestionControl
	if cc == "" {
		cc = CongestionCubic
	}
	inbound["congestion_control"] = cc
	if data.AuthTimeout != "" {
		inbound["auth_timeout"] = data.AuthTimeout
	}
	if data.ZeroRTTHandshake {
		inbound["zero_rtt_handshake"] = true
	}
	if data.Heartbeat != "" {
		inbound["heartbeat"] = data.Heartbeat
	}
	applyQUICFields(inbound, data)
	return inbound, nil
}

// ClientURI returns a tuic:// connection URI for the client.
func (a *Adapter) ClientURI(vpn domain.VPNConfig, _ []domain.ClientConfig, client domain.ClientConfig, serverHost string) (string, error) {
	return BuildClientURI(vpn, client, serverHost)
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
func (a *Adapter) FirewallProtos() []string { return []string{"udp"} }

// BuildClientURI constructs a tuic:// share link.
func BuildClientURI(vpn domain.VPNConfig, client domain.ClientConfig, serverHost string) (string, error) {
	if err := (&Adapter{}).ValidateClient(client); err != nil {
		return "", err
	}
	data, err := parseProtocolData(vpn.ProtocolData)
	if err != nil {
		return "", err
	}
	host := listen.ProxyHost(vpn, serverHost)
	q := url.Values{}
	if data.ServerName != "" {
		q.Set("sni", data.ServerName)
	}
	cc := data.CongestionControl
	if cc == "" {
		cc = CongestionCubic
	}
	q.Set("congestion_control", cc)
	q.Set("udp_relay_mode", "native")
	if len(data.ALPN) > 0 {
		q.Set("alpn", strings.Join(data.ALPN, ","))
	}
	if protocol.ShareLinkInsecureTLS(TLSMode(data)) {
		q.Set("allow_insecure", "1")
	}
	fragment := client.Name
	if fragment == "" {
		fragment = client.Username
	}
	u := &url.URL{
		Scheme:   "tuic",
		User:     url.UserPassword(client.Username, client.Password),
		Host:     net.JoinHostPort(host, strconv.Itoa(vpn.Listen.ListenPort)),
		RawQuery: q.Encode(),
		Fragment: fragment,
	}
	return u.String(), nil
}
