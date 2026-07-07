package orchestration

import (
	"fmt"
	"strings"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/service"
)

// CreateVPNRequest is a transport-agnostic request for building CreateVPNInput.
type CreateVPNRequest struct {
	Name              string
	Protocol          string
	ClientHost        string
	Listen            domain.ListenOptions
	Enabled           bool
	InitialClientName string

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

	HTTP        HTTPCreateOptions
	Shadowsocks ShadowsocksCreateOptions
	Trojan      TrojanCreateOptions
	Wireguard   WireguardCreateOptions
	VMess       VMessCreateOptions
	VLESS       VLESSCreateOptions
	Hysteria2   Hysteria2CreateOptions
	TUIC        TUICCreateOptions

	// Requested multiplex toggles are kept separately so validation can reject
	// unsupported protocol combinations before options are normalized.
	MultiplexRequested               bool
	MultiplexPaddingRequested        bool
	MultiplexBrutalRequested         bool
	MultiplexBrutalUpMbpsRequested   int
	MultiplexBrutalDownMbpsRequested int
}

// BuildCreateVPNInput assembles canonical CreateVPNInput from unified request fields.
func BuildCreateVPNInput(req CreateVPNRequest) CreateVPNInput {
	protocolName := req.Protocol
	if protocolName == "" {
		protocolName = string(domain.ProtocolSOCKS5)
	}

	listen := req.Listen
	if listen.Listen == "" {
		listen.Listen = "0.0.0.0"
	}
	if listen.ListenPort == 0 {
		listen.ListenPort = defaultListenPort(protocolName)
	}

	in := CreateVPNInput{
		Name:              req.Name,
		Protocol:          protocolName,
		ClientHost:        req.ClientHost,
		Listen:            listen,
		Enabled:           req.Enabled,
		InitialClientName: req.InitialClientName,

		HTTPTLS: req.HTTPTLS,
		HTTP:    req.HTTP,
	}
	if req.HTTPTLS {
		in.HTTP.TLS = true
	}

	switch protocolName {
	case string(domain.ProtocolShadowsocks):
		in.SSMethod = req.SSMethod
		in.SSPlugin = req.SSPlugin
		in.SSPluginOpts = req.SSPluginOpts
		in.SSMultiplex = req.SSMultiplex
		in.SSMultiplexPadding = req.SSMultiplexPadding
		in.SSShadowTLS = req.SSShadowTLS
		in.SSShadowTLSHandshake = req.SSShadowTLSHandshake
		in.SSShadowTLSHandshakePort = req.SSShadowTLSHandshakePort
		in.SSShadowTLSStrictMode = req.SSShadowTLSStrictMode
		in.Shadowsocks = req.Shadowsocks
		if in.Shadowsocks.ListenPort == 0 {
			in.Shadowsocks.ListenPort = listen.ListenPort
		}
	case string(domain.ProtocolTrojan):
		in.Trojan = req.Trojan
	case string(domain.ProtocolWireGuard):
		in.Wireguard = req.Wireguard
	case string(domain.ProtocolVMess):
		in.VMess = req.VMess
	case string(domain.ProtocolVLESS):
		in.VLESS = req.VLESS
	case string(domain.ProtocolHysteria2):
		in.Hysteria2 = req.Hysteria2
	case string(domain.ProtocolTUIC):
		in.TUIC = req.TUIC
	}

	return service.NormalizeCreateVPNInput(in)
}

// BuildUpdateVPNInput centralizes EditVPN request rules from adapters.
func BuildUpdateVPNInput(req UpdateVPNRequest) (UpdateVPNInput, error) {
	if req.ClientHost != nil && req.ClearClientHost {
		return UpdateVPNInput{}, fmt.Errorf("--client-host and --clear-client-host are mutually exclusive")
	}

	in := UpdateVPNInput{Listen: req.Listen}
	if req.Name != nil && strings.TrimSpace(*req.Name) != "" {
		in.Name = req.Name
	}
	if req.Enabled != nil {
		in.Enabled = req.Enabled
	}
	if req.HTTPTLS != nil {
		in.HTTPTLS = req.HTTPTLS
	}
	if req.ClearClientHost {
		cleared := ""
		in.ClientHost = &cleared
	} else if req.ClientHost != nil {
		in.ClientHost = req.ClientHost
	}
	return in, nil
}

// BuildUpdateClientInput centralizes EditClient request rules from adapters.
func BuildUpdateClientInput(req UpdateClientRequest) UpdateClientInput {
	in := UpdateClientInput{
		VPNName: req.VPNName,
		Name:    req.Name,
	}
	if req.NewName != nil && strings.TrimSpace(*req.NewName) != "" {
		in.NewName = req.NewName
	}
	if req.Username != nil {
		in.Username = req.Username
	}
	if req.Password != nil {
		in.Password = req.Password
	}
	if req.Enabled != nil {
		in.Enabled = req.Enabled
	}
	return in
}

// UpdateVPNRequest is a transport-agnostic request for building UpdateVPNInput.
type UpdateVPNRequest struct {
	Name            *string
	Listen          *domain.ListenOptions
	Enabled         *bool
	HTTPTLS         *bool
	ClientHost      *string
	ClearClientHost bool
}

// UpdateClientRequest is a transport-agnostic request for building UpdateClientInput.
type UpdateClientRequest struct {
	VPNName  string
	Name     string
	NewName  *string
	Username *string
	Password *string
	Enabled  *bool
	Reapply  bool
}

func defaultListenPort(protocolName string) int {
	switch domain.ProtocolType(protocolName) {
	case domain.ProtocolHTTP:
		return 8080
	case domain.ProtocolTrojan, domain.ProtocolVMess, domain.ProtocolVLESS, domain.ProtocolHysteria2, domain.ProtocolTUIC:
		return 443
	case domain.ProtocolShadowsocks:
		return 8388
	case domain.ProtocolWireGuard:
		return 51820
	default:
		return 1080
	}
}

// DefaultListenPort returns canonical default port for protocol.
func DefaultListenPort(protocolName string) int {
	return defaultListenPort(protocolName)
}
