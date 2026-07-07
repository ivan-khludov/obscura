package shadowsocks

import (
	"fmt"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
)

const previewServerPassword = "preview-shadowsocks-server-key"

var (
	newKeyGen     = func() *KeyGen { return &KeyGen{} }
	newOptionsGen = func() *OptionsGen { return &OptionsGen{} }
)

// CreateOptions holds Shadowsocks-specific create parameters.
type CreateOptions struct {
	Method                 string
	Plugin                 string
	PluginOpts             string
	Multiplex              bool
	MultiplexPadding       bool
	ShadowTLS              bool
	ShadowTLSHandshake     string
	ShadowTLSHandshakePort int
	ShadowTLSStrictMode    bool
	ListenPort             int
}

// BuildProtocolData builds and validates Shadowsocks protocol data.
func (a *Adapter) BuildProtocolData(_ protocol.BuildContext, spec domain.CreateVPNSpec, _ string, mode protocol.BuildMode) ([]byte, error) {
	opts, err := createOptionsFromSpec(spec)
	if err != nil {
		return nil, err
	}
	data, err := buildCreateProtocolData(opts, mode)
	if err != nil {
		return nil, err
	}
	if err := ValidateOptions(data); err != nil {
		return nil, err
	}
	return MarshalProtocolData(data)
}

// NeedsInitialClient reports whether Shadowsocks requires an enabled client.
func (a *Adapter) NeedsInitialClient(_ domain.VPNConfig) bool {
	return true
}

func createOptionsFromSpec(spec domain.CreateVPNSpec) (CreateOptions, error) {
	switch opts := spec.ProtocolOptions.(type) {
	case nil:
		return CreateOptions{}, nil
	case CreateOptions:
		return opts, nil
	case *CreateOptions:
		if opts == nil {
			return CreateOptions{}, nil
		}
		return *opts, nil
	default:
		return CreateOptions{}, fmt.Errorf("shadowsocks create options have unexpected type %T", spec.ProtocolOptions)
	}
}

func buildCreateProtocolData(opts CreateOptions, mode protocol.BuildMode) (ProtocolData, error) {
	method := opts.Method
	if method == "" {
		method = DefaultMethod
	}
	if !SupportsMultiUser(method) {
		return ProtocolData{}, fmt.Errorf("method %q does not support multi-user in sing-box; use 2022-blake3-aes-128-gcm or 2022-blake3-aes-256-gcm", method)
	}
	serverPassword := previewServerPassword
	if mode == protocol.BuildModeProvision {
		var err error
		serverPassword, err = newKeyGen().GenerateKey(method)
		if err != nil {
			return ProtocolData{}, fmt.Errorf("generate shadowsocks server key: %w", err)
		}
	}
	data := ProtocolData{
		Method:                 method,
		ServerPassword:         serverPassword,
		Plugin:                 opts.Plugin,
		PluginOpts:             opts.PluginOpts,
		Multiplex:              opts.Multiplex,
		MultiplexPadding:       opts.MultiplexPadding,
		ShadowTLS:              opts.ShadowTLS,
		ShadowTLSHandshake:     opts.ShadowTLSHandshake,
		ShadowTLSHandshakePort: opts.ShadowTLSHandshakePort,
		ShadowTLSStrictMode:    opts.ShadowTLSStrictMode,
	}
	if data.ShadowTLS {
		if data.ShadowTLSHandshake == "" {
			data.ShadowTLSHandshake = DefaultShadowTLSHandshake
		}
		if mode == protocol.BuildModeProvision {
			password, err := newOptionsGen().GenerateShadowTLSPassword()
			if err != nil {
				return ProtocolData{}, fmt.Errorf("generate shadowtls password: %w", err)
			}
			data.ShadowTLSPassword = password
			backendPort, err := newOptionsGen().GenerateBackendPort(opts.ListenPort)
			if err != nil {
				return ProtocolData{}, err
			}
			data.ShadowTLSBackendPort = backendPort
		} else {
			data.ShadowTLSPassword = "preview-shadowtls-password"
			data.ShadowTLSBackendPort = opts.ListenPort + 10000
			if data.ShadowTLSBackendPort > 65535 {
				data.ShadowTLSBackendPort = 20000 + opts.ListenPort%40000
			}
		}
	}
	return data, nil
}
