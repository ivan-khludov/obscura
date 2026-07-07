package service

import (
	"time"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/httpproxy"
	"github.com/ivan-khludov/obscura/internal/protocol/shadowsocks"
)

// CreateVPNInput describes parameters for creating a VPN instance.
type CreateVPNInput struct {
	Name                     string
	Protocol                 string
	ClientHost               string
	Listen                   domain.ListenOptions
	Enabled                  bool
	InitialClientName        string
	HTTP                     HTTPCreateOptions
	Shadowsocks              ShadowsocksCreateOptions
	HTTPTLS                  bool
	SSMethod                 string
	SSPlugin                 string
	SSPluginOpts             string
	SSMultiplex              bool
	SSMultiplexPadding       bool
	SSShadowTLS              bool
	SSShadowTLSHandshake     string
	SSShadowTLSHandshakePort int
	SSShadowTLSStrictMode    bool
	Trojan                   TrojanCreateOptions
	Wireguard                WireguardCreateOptions
	VMess                    VMessCreateOptions
	VLESS                    VLESSCreateOptions
	Hysteria2                Hysteria2CreateOptions
	TUIC                     TUICCreateOptions
}

// HTTPCreateOptions holds HTTP-specific create parameters.
type HTTPCreateOptions = httpproxy.CreateOptions

// ShadowsocksCreateOptions holds shadowsocks-specific create parameters.
type ShadowsocksCreateOptions = shadowsocks.CreateOptions

// CreateVPNResult describes a created VPN and its initial client when required.
type CreateVPNResult struct {
	VPN    *domain.VPN    `json:"vpn"`
	Client *domain.Client `json:"client,omitempty"`
	URI    string         `json:"uri,omitempty"`
}

// UpdateVPNInput describes VPN field updates.
type UpdateVPNInput struct {
	Name       *string
	ClientHost *string
	Listen     *domain.ListenOptions
	Enabled    *bool
	HTTPTLS    *bool
}

// AddClientInput describes parameters for adding a client.
type AddClientInput struct {
	VPNName  string
	Name     string
	Username string
	Password string
}

// UpdateClientInput describes client field updates.
type UpdateClientInput struct {
	VPNName  string
	Name     string
	NewName  *string
	Username *string
	Password *string
	Enabled  *bool
}

// BootstrapOptions configures optional bootstrap steps.
type BootstrapOptions struct {
	WithFallbackStub bool
	Progress         func(BootstrapProgress)
}

// BackupEntry describes a backup archive on disk.
type BackupEntry struct {
	Name    string    `json:"name"`
	Path    string    `json:"path"`
	ModTime time.Time `json:"mod_time"`
}
