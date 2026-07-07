package httpproxy

import (
	"fmt"
	"path/filepath"

	"github.com/ivan-khludov/obscura/internal/certs"
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
)

const (
	previewCertPath = "/preview/obscura.crt"
	previewKeyPath  = "/preview/obscura.key"
)

// CreateOptions holds HTTP-specific create parameters.
type CreateOptions struct {
	TLS bool
}

// BuildProtocolData builds and validates HTTP protocol data.
func (a *Adapter) BuildProtocolData(ctx protocol.BuildContext, spec domain.CreateVPNSpec, tag string, mode protocol.BuildMode) ([]byte, error) {
	opts, err := createOptionsFromSpec(spec)
	if err != nil {
		return nil, err
	}
	if !opts.TLS {
		return []byte("{}"), nil
	}
	data := ProtocolData{TLS: true}
	switch mode {
	case protocol.BuildModePreview:
		data.CertPath = previewCertPath
		data.KeyPath = previewKeyPath
	case protocol.BuildModeProvision:
		certPath := filepath.Join(ctx.DataDir(), "certs", tag+".crt")
		keyPath := filepath.Join(ctx.DataDir(), "certs", tag+".key")
		if err := certs.GenerateSelfSigned(ctx.ServerHost(), certPath, keyPath); err != nil {
			return nil, fmt.Errorf("generate tls certificate: %w", err)
		}
		data.CertPath = certPath
		data.KeyPath = keyPath
		ctx.AddCertPath(certPath)
		ctx.AddCertPath(keyPath)
		if err := ctx.SaveManifest(); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown build mode %d", mode)
	}
	return MarshalProtocolData(data)
}

// NeedsInitialClient reports whether HTTP requires an enabled client.
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
		return CreateOptions{}, fmt.Errorf("http create options have unexpected type %T", spec.ProtocolOptions)
	}
}
