// Package protocol defines the pluggable protocol adapter interface and registry.
package protocol

import "github.com/ivan-khludov/obscura/internal/domain"

// BuildMode selects whether protocol data should provision runtime assets.
type BuildMode int

const (
	// BuildModePreview validates and builds protocol data without side effects.
	BuildModePreview BuildMode = iota
	// BuildModeProvision builds protocol data and provisions required assets.
	BuildModeProvision
)

// BuildContext exposes runtime services needed by protocol data builders.
type BuildContext interface {
	ServerHost() string
	DataDir() string
	GeneratePassword(length int) (string, error)
	AddCertPath(path string)
	SaveManifest() error
	SingBoxBinary() string
}

// DataBuilder is optionally implemented by protocol adapters that own create-time
// protocol data assembly.
type DataBuilder interface {
	BuildProtocolData(ctx BuildContext, spec domain.CreateVPNSpec, tag string, mode BuildMode) ([]byte, error)
	NeedsInitialClient(vpn domain.VPNConfig) bool
}

// Protocol defines validation, rendering, and client URI generation for a proxy protocol.
type Protocol interface {
	Type() string
	ValidateVPN(vpn domain.VPNConfig, clients []domain.ClientConfig) error
	ValidateClient(client domain.ClientConfig) error
	RenderInbound(vpn domain.VPNConfig, clients []domain.ClientConfig) (map[string]any, error)
	RenderEndpoints(vpn domain.VPNConfig, clients []domain.ClientConfig) ([]map[string]any, error)
	AdditionalInbounds(vpn domain.VPNConfig, clients []domain.ClientConfig) ([]map[string]any, error)
	ClientURI(vpn domain.VPNConfig, clients []domain.ClientConfig, client domain.ClientConfig, serverHost string) (string, error)
	ClientQRContent(vpn domain.VPNConfig, clients []domain.ClientConfig, client domain.ClientConfig, serverHost string) (string, error)
	DefaultListen() domain.ListenOptions
	SupportedListenFields() []string
	RouteExtensions(vpn domain.VPNConfig) ([]map[string]any, error)
	UsesInbound() bool
	FirewallProtos() []string
}
