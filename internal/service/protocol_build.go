package service

import (
	"fmt"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
)

// createSpec adapts the legacy CreateVPNInput to the protocol-neutral create shape.
func createSpec(in CreateVPNInput) domain.CreateVPNSpec {
	in = NormalizeCreateVPNInput(in)
	spec := domain.CreateVPNSpec{
		Name:              in.Name,
		Protocol:          domain.ProtocolType(in.Protocol),
		ClientHost:        in.ClientHost,
		Listen:            in.Listen,
		Enabled:           in.Enabled,
		InitialClientName: in.InitialClientName,
		ProtocolOptions:   protocolOptionsFromInput(in),
	}
	return spec
}

func protocolOptionsFromInput(in CreateVPNInput) any {
	switch domain.ProtocolType(in.Protocol) {
	case domain.ProtocolHTTP:
		if hasHTTPOptions(in.HTTP) {
			return in.HTTP
		}
		return HTTPCreateOptions{TLS: in.HTTPTLS}
	case domain.ProtocolShadowsocks:
		if hasShadowsocksOptions(in.Shadowsocks) {
			return in.Shadowsocks
		}
		return ShadowsocksCreateOptions{
			Method:                 in.SSMethod,
			Plugin:                 in.SSPlugin,
			PluginOpts:             in.SSPluginOpts,
			Multiplex:              in.SSMultiplex,
			MultiplexPadding:       in.SSMultiplexPadding,
			ShadowTLS:              in.SSShadowTLS,
			ShadowTLSHandshake:     in.SSShadowTLSHandshake,
			ShadowTLSHandshakePort: in.SSShadowTLSHandshakePort,
			ShadowTLSStrictMode:    in.SSShadowTLSStrictMode,
			ListenPort:             in.Listen.ListenPort,
		}
	case domain.ProtocolTrojan:
		return in.Trojan
	case domain.ProtocolWireGuard:
		return in.Wireguard
	case domain.ProtocolVMess:
		return in.VMess
	case domain.ProtocolVLESS:
		return in.VLESS
	case domain.ProtocolHysteria2:
		return in.Hysteria2
	case domain.ProtocolTUIC:
		return in.TUIC
	default:
		return nil
	}
}

func (s *Service) buildProtocolData(in CreateVPNInput, tag string, mode protocol.BuildMode) ([]byte, error) {
	adapter, err := s.registry.Get(in.Protocol)
	if err != nil {
		return nil, err
	}
	builder, ok := adapter.(protocol.DataBuilder)
	if !ok {
		return nil, fmt.Errorf("protocol %q does not implement create data builder", in.Protocol)
	}
	return builder.BuildProtocolData(s, createSpec(in), tag, mode)
}

// ServerHost returns the configured public server host for protocol builders.
func (s *Service) ServerHost() string {
	return s.app.ServerHost
}

// DataDir returns the runtime data directory for protocol builders.
func (s *Service) DataDir() string {
	return s.app.DataDir
}

// GeneratePassword generates a URL-safe random password for protocol builders.
func (s *Service) GeneratePassword(length int) (string, error) {
	return s.passwordGen.randomPassword(length)
}

// AddCertPath records a certificate path in the install manifest.
func (s *Service) AddCertPath(path string) {
	s.manifest.AddCertPath(path)
}

// SaveManifest persists the install manifest.
func (s *Service) SaveManifest() error {
	return s.manifest.Save()
}

// SingBoxBinary resolves the sing-box binary path for protocol builders.
func (s *Service) SingBoxBinary() string {
	return s.singBoxBinary()
}
