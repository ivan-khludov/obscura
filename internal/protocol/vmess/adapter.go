// Package vmess implements the VMess inbound protocol adapter for sing-box.
package vmess

import (
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/protocol/listen"
)

const typeName = "vmess"

// Adapter implements protocol.Protocol for sing-box VMess inbound.
type Adapter struct{}

// Type returns the protocol identifier used in VPN records.
func (a *Adapter) Type() string {
	return typeName
}

// DefaultListen returns default listen options for VMess inbounds.
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

// ValidateVPN checks VPN and client configuration for VMess inbounds.
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
	return validateEnabledClients(data, clients)
}

// ValidateClient checks a single client credential set.
func (a *Adapter) ValidateClient(client domain.ClientConfig) error {
	if client.Password == "" {
		return errors.New("uuid is required")
	}
	if _, err := uuid.Parse(client.Password); err != nil {
		return fmt.Errorf("invalid uuid: %w", err)
	}
	if client.Username != "" {
		if _, err := clientAlterID(ProtocolData{}, client); err != nil {
			return err
		}
	}
	return nil
}

// validateEnabledClients validates protocol options or configuration consistency.
func validateEnabledClients(data ProtocolData, clients []domain.ClientConfig) error {
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
		return errors.New("at least one enabled client is required for VMess authentication")
	}
	if _, err := UsersFromClients(data, clients); err != nil {
		return err
	}
	return nil
}

// RenderInbound builds a sing-box VMess inbound map from VPN and client state.
func (a *Adapter) RenderInbound(vpn domain.VPNConfig, clients []domain.ClientConfig) (map[string]any, error) {
	if err := a.ValidateVPN(vpn, clients); err != nil {
		return nil, err
	}
	data, err := ParseProtocolData(vpn.ProtocolData)
	if err != nil {
		return nil, err
	}
	users, err := UsersFromClients(data, clients)
	if err != nil {
		return nil, err
	}
	inbound := map[string]any{
		"type":        "vmess",
		"tag":         vpn.Tag,
		"listen":      vpn.Listen.Listen,
		"listen_port": vpn.Listen.ListenPort,
		"users":       users,
	}
	listen.ApplyOptionalFields(inbound, vpn.Listen)
	if !data.TLSDisabled {
		inbound["tls"] = renderTLS(data)
	}
	if data.Multiplex {
		inbound["multiplex"] = renderMultiplex(data)
	}
	if transport := renderTransport(data); transport != nil {
		inbound["transport"] = transport
	}
	return inbound, nil
}

// ClientURI returns a vmess:// connection URI for the client.
func (a *Adapter) ClientURI(vpn domain.VPNConfig, _ []domain.ClientConfig, client domain.ClientConfig, serverHost string) (string, error) {
	if err := a.ValidateClient(client); err != nil {
		return "", err
	}
	data, err := ParseProtocolData(vpn.ProtocolData)
	if err != nil {
		return "", err
	}
	return buildShareLink(vpn, data, client, serverHost)
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
