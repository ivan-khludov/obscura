// Package hysteria2 implements the Hysteria2 inbound protocol adapter for sing-box.
package hysteria2

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/protocol/listen"
)

const typeName = "hysteria2"

var parseProtocolData = ParseProtocolData

// Adapter implements protocol.Protocol for sing-box Hysteria2 inbound.
type Adapter struct{}

// Type returns the protocol identifier used in VPN records.
func (a *Adapter) Type() string {
	return typeName
}

// DefaultListen returns default listen options for Hysteria2 inbounds.
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

// ValidateVPN checks VPN and client configuration for Hysteria2 inbounds.
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
		return errors.New("at least one enabled client is required for Hysteria2 authentication")
	}
	return nil
}

// RenderInbound builds a sing-box Hysteria2 inbound map from VPN and client state.
func (a *Adapter) RenderInbound(vpn domain.VPNConfig, clients []domain.ClientConfig) (map[string]any, error) {
	if err := a.ValidateVPN(vpn, clients); err != nil {
		return nil, err
	}
	data, err := parseProtocolData(vpn.ProtocolData)
	if err != nil {
		return nil, err
	}
	inbound := map[string]any{
		"type":        "hysteria2",
		"tag":         vpn.Tag,
		"listen":      vpn.Listen.Listen,
		"listen_port": vpn.Listen.ListenPort,
		"users":       UsersFromClients(clients),
		"tls":         renderTLS(data),
	}
	listen.ApplyOptionalFields(inbound, vpn.Listen)
	if data.UpMbps > 0 {
		inbound["up_mbps"] = data.UpMbps
	}
	if data.DownMbps > 0 {
		inbound["down_mbps"] = data.DownMbps
	}
	if data.IgnoreClientBandwidth {
		inbound["ignore_client_bandwidth"] = true
	}
	if obfs := renderObfs(data); obfs != nil {
		inbound["obfs"] = obfs
	}
	if masq := renderMasquerade(data); masq != nil {
		inbound["masquerade"] = masq
	}
	if data.BrutalDebug {
		inbound["brutal_debug"] = true
	}
	if data.BBRProfile != "" {
		inbound["bbr_profile"] = data.BBRProfile
	}
	if realm := renderRealm(data.Realm); realm != nil {
		inbound["realm"] = realm
	}
	applyQUICFields(inbound, data)
	return inbound, nil
}

// ClientURI returns a hysteria2:// connection URI for the client.
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

// BuildClientURI constructs a hysteria2:// share link.
func BuildClientURI(vpn domain.VPNConfig, client domain.ClientConfig, serverHost string) (string, error) {
	if client.Password == "" {
		return "", errors.New("password is required")
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
	if data.ObfsPassword != "" {
		q.Set("obfs", "salamander")
		q.Set("obfs-password", data.ObfsPassword)
	}
	if protocol.ShareLinkInsecureTLS(TLSMode(data)) {
		q.Set("insecure", "1")
	}
	if data.UpMbps > 0 {
		q.Set("upmbps", strconv.Itoa(data.UpMbps))
	}
	if data.DownMbps > 0 {
		q.Set("downmbps", strconv.Itoa(data.DownMbps))
	}
	userInfo := url.UserPassword(client.Name, client.Password)
	if client.Name == "" {
		userInfo = url.User(client.Password)
	}
	fragment := client.Name
	if fragment == "" {
		fragment = client.Username
	}
	u := &url.URL{
		Scheme:   "hysteria2",
		User:     userInfo,
		Host:     net.JoinHostPort(host, strconv.Itoa(vpn.Listen.ListenPort)),
		RawQuery: q.Encode(),
		Fragment: fragment,
	}
	return u.String(), nil
}
