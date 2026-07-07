// Package trojan implements the Trojan inbound protocol adapter for sing-box.
package trojan

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/protocol/listen"
)

const typeName = "trojan"

// Adapter implements protocol.Protocol for sing-box Trojan inbound.
type Adapter struct{}

// Type returns the protocol identifier used in VPN records.
func (a *Adapter) Type() string {
	return typeName
}

// DefaultListen returns default listen options for Trojan inbounds.
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

// ValidateVPN checks VPN and client configuration for Trojan inbounds.
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
		return errors.New("at least one enabled client is required for Trojan authentication")
	}
	return nil
}

// RenderInbound builds a sing-box Trojan inbound map from VPN and client state.
func (a *Adapter) RenderInbound(vpn domain.VPNConfig, clients []domain.ClientConfig) (map[string]any, error) {
	if err := a.ValidateVPN(vpn, clients); err != nil {
		return nil, err
	}
	data, err := parseProtocolDataForRender(vpn.ProtocolData)
	if err != nil {
		return nil, err
	}
	inbound := map[string]any{
		"type":        "trojan",
		"tag":         vpn.Tag,
		"listen":      vpn.Listen.Listen,
		"listen_port": vpn.Listen.ListenPort,
		"users":       UsersFromClients(clients),
		"tls":         renderTLS(data),
	}
	listen.ApplyOptionalFields(inbound, vpn.Listen)
	if data.Multiplex {
		inbound["multiplex"] = renderMultiplex(data)
	}
	fallback, fallbackForALPN := renderFallback(data)
	if fallback != nil {
		inbound["fallback"] = fallback
	}
	if fallbackForALPN != nil {
		inbound["fallback_for_alpn"] = fallbackForALPN
	}
	if transport := renderTransport(data); transport != nil {
		inbound["transport"] = transport
	}
	return inbound, nil
}

// ClientURI returns a trojan:// connection URI for the client.
func (a *Adapter) ClientURI(vpn domain.VPNConfig, _ []domain.ClientConfig, client domain.ClientConfig, serverHost string) (string, error) {
	if err := a.ValidateClient(client); err != nil {
		return "", err
	}
	data, err := ParseProtocolData(vpn.ProtocolData)
	if err != nil {
		return "", err
	}
	host := listen.ProxyHost(vpn, serverHost)
	q := url.Values{}
	q.Set("security", "tls")
	if data.ServerName != "" {
		q.Set("sni", data.ServerName)
	}
	if len(data.ALPN) > 0 {
		q.Set("alpn", strings.Join(data.ALPN, ","))
	}
	transportType := data.TransportType
	if transportType == "" {
		transportType = "tcp"
	}
	q.Set("type", transportType)
	if data.TransportWS != nil && data.TransportWS.Path != "" {
		q.Set("path", data.TransportWS.Path)
	}
	if data.TransportHTTP != nil && data.TransportHTTP.Path != "" {
		q.Set("path", data.TransportHTTP.Path)
	}
	if data.TransportHTTPUpgrade != nil {
		if data.TransportHTTPUpgrade.Path != "" {
			q.Set("path", data.TransportHTTPUpgrade.Path)
		}
		if data.TransportHTTPUpgrade.Host != "" {
			q.Set("host", data.TransportHTTPUpgrade.Host)
		}
	}
	if data.TransportGRPC != nil && data.TransportGRPC.ServiceName != "" {
		q.Set("serviceName", data.TransportGRPC.ServiceName)
	}
	if data.Multiplex {
		q.Set("mux", "true")
	}
	if protocol.ShareLinkInsecureTLS(TLSMode(data)) {
		q.Set("allowInsecure", "1")
	}
	fragment := client.Name
	if fragment == "" {
		fragment = client.Username
	}
	u := &url.URL{
		Scheme:   "trojan",
		User:     url.User(client.Password),
		Host:     net.JoinHostPort(host, strconv.Itoa(vpn.Listen.ListenPort)),
		RawQuery: q.Encode(),
		Fragment: fragment,
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
