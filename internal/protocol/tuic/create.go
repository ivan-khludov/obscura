package tuic

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ivan-khludov/obscura/internal/certs"
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
)

const (
	previewCertPath   = "/preview/obscura.crt"
	previewKeyPath    = "/preview/obscura.key"
	previewECHKeyPath = "/preview/obscura-ech.key"
)

// CreateOptions holds TUIC-specific create parameters.
type CreateOptions struct {
	ServerName                       string
	ALPN                             []string
	CertPath                         string
	KeyPath                          string
	MinVersion                       string
	MaxVersion                       string
	CipherSuites                     []string
	CurvePreferences                 []string
	ClientAuthentication             string
	ClientCertificatePaths           []string
	ClientCertificatePublicKeySHA256 []string
	KernelTX                         bool
	KernelRX                         bool
	HandshakeTimeout                 string
	ACMEDomains                      []string
	ACMEEmail                        string
	ACMEProvider                     string
	ACMEDataDirectory                string
	ACMEDefaultServerName            string
	ACMEDisableHTTPChallenge         bool
	ACMEDisableTLSALPNChallenge      bool
	ACMEAlternativeHTTPPort          int
	ACMEAlternativeTLSPort           int
	ECH                              bool
	ECHKeyPath                       string
	CongestionControl                string
	AuthTimeout                      string
	ZeroRTTHandshake                 bool
	Heartbeat                        string
	InitialPacketSize                int
	DisablePathMTUDiscovery          bool
	HTTP2IdleTimeout                 string
	HTTP2KeepAlivePeriod             string
	HTTP2StreamReceiveWindow         string
	HTTP2ConnectionReceiveWindow     string
	HTTP2MaxConcurrentStreams        int
}

// BuildProtocolData builds and validates TUIC protocol data.
func (a *Adapter) BuildProtocolData(ctx protocol.BuildContext, spec domain.CreateVPNSpec, tag string, mode protocol.BuildMode) ([]byte, error) {
	opts, err := createOptionsFromSpec(spec)
	if err != nil {
		return nil, err
	}
	data := buildCreateProtocolData(ctx.ServerHost(), opts)
	switch mode {
	case protocol.BuildModePreview:
		applyPreviewTLS(&data, opts)
	case protocol.BuildModeProvision:
		if err := setupTLS(ctx, &data, tag, opts); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown build mode %d", mode)
	}
	if err := ValidateOptions(data); err != nil {
		return nil, err
	}
	return MarshalProtocolData(data)
}

// NeedsInitialClient reports whether TUIC requires an enabled client.
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
		return CreateOptions{}, fmt.Errorf("tuic create options have unexpected type %T", spec.ProtocolOptions)
	}
}

func buildCreateProtocolData(serverHost string, t CreateOptions) ProtocolData {
	data := ProtocolData{
		ServerName:                       t.ServerName,
		ALPN:                             t.ALPN,
		CertPath:                         t.CertPath,
		KeyPath:                          t.KeyPath,
		MinVersion:                       t.MinVersion,
		MaxVersion:                       t.MaxVersion,
		CipherSuites:                     t.CipherSuites,
		CurvePreferences:                 t.CurvePreferences,
		ClientAuthentication:             t.ClientAuthentication,
		ClientCertificatePaths:           t.ClientCertificatePaths,
		ClientCertificatePublicKeySHA256: t.ClientCertificatePublicKeySHA256,
		KernelTX:                         t.KernelTX,
		KernelRX:                         t.KernelRX,
		HandshakeTimeout:                 t.HandshakeTimeout,
		ECHEnabled:                       t.ECH,
		ECHKeyPath:                       t.ECHKeyPath,
		CongestionControl:                t.CongestionControl,
		AuthTimeout:                      t.AuthTimeout,
		ZeroRTTHandshake:                 t.ZeroRTTHandshake,
		Heartbeat:                        t.Heartbeat,
		InitialPacketSize:                t.InitialPacketSize,
		DisablePathMTUDiscovery:          t.DisablePathMTUDiscovery,
	}
	if data.ServerName == "" {
		data.ServerName = serverHost
	}
	if len(data.ALPN) == 0 {
		data.ALPN = append([]string{}, DefaultALPN...)
	}
	if len(t.ACMEDomains) > 0 {
		data.ACME = &ACMEOptions{
			Domains:                 t.ACMEDomains,
			Email:                   t.ACMEEmail,
			Provider:                t.ACMEProvider,
			DataDirectory:           t.ACMEDataDirectory,
			DefaultServerName:       t.ACMEDefaultServerName,
			DisableHTTPChallenge:    t.ACMEDisableHTTPChallenge,
			DisableTLSALPNChallenge: t.ACMEDisableTLSALPNChallenge,
			AlternativeHTTPPort:     t.ACMEAlternativeHTTPPort,
			AlternativeTLSPort:      t.ACMEAlternativeTLSPort,
		}
	}
	if t.HTTP2IdleTimeout != "" || t.HTTP2KeepAlivePeriod != "" ||
		t.HTTP2StreamReceiveWindow != "" || t.HTTP2ConnectionReceiveWindow != "" ||
		t.HTTP2MaxConcurrentStreams > 0 {
		data.HTTP2 = &HTTP2Options{
			IdleTimeout:             t.HTTP2IdleTimeout,
			KeepAlivePeriod:         t.HTTP2KeepAlivePeriod,
			StreamReceiveWindow:     t.HTTP2StreamReceiveWindow,
			ConnectionReceiveWindow: t.HTTP2ConnectionReceiveWindow,
			MaxConcurrentStreams:    t.HTTP2MaxConcurrentStreams,
		}
	}
	return data
}

func applyPreviewTLS(data *ProtocolData, t CreateOptions) {
	if data.ACME != nil && len(data.ACME.Domains) > 0 {
		if t.ECH && data.ECHKeyPath == "" {
			data.ECHEnabled = true
			data.ECHKeyPath = previewECHKeyPath
		}
		return
	}
	if data.CertPath != "" && data.KeyPath != "" {
		if t.ECH && data.ECHKeyPath == "" {
			data.ECHEnabled = true
			data.ECHKeyPath = previewECHKeyPath
		}
		return
	}
	data.CertPath = previewCertPath
	data.KeyPath = previewKeyPath
	if t.ECH {
		data.ECHEnabled = true
		data.ECHKeyPath = previewECHKeyPath
	}
}

func setupTLS(ctx protocol.BuildContext, data *ProtocolData, tag string, t CreateOptions) error {
	if data.ACME != nil && len(data.ACME.Domains) > 0 {
		if t.ECH {
			return setupECH(ctx, data, tag)
		}
		return nil
	}
	if data.CertPath != "" && data.KeyPath != "" {
		ctx.AddCertPath(data.CertPath)
		ctx.AddCertPath(data.KeyPath)
		if err := ctx.SaveManifest(); err != nil {
			return err
		}
		if t.ECH {
			return setupECH(ctx, data, tag)
		}
		return nil
	}
	certPath := filepath.Join(ctx.DataDir(), "certs", tag+".crt")
	keyPath := filepath.Join(ctx.DataDir(), "certs", tag+".key")
	if err := certs.GenerateSelfSigned(data.ServerName, certPath, keyPath); err != nil {
		return fmt.Errorf("generate tls certificate: %w", err)
	}
	data.CertPath = certPath
	data.KeyPath = keyPath
	ctx.AddCertPath(certPath)
	ctx.AddCertPath(keyPath)
	if err := ctx.SaveManifest(); err != nil {
		return err
	}
	if t.ECH {
		return setupECH(ctx, data, tag)
	}
	return nil
}

func setupECH(ctx protocol.BuildContext, data *ProtocolData, tag string) error {
	data.ECHEnabled = true
	if data.ECHKeyPath != "" {
		return nil
	}
	echKeyPath := filepath.Join(ctx.DataDir(), "certs", tag+"-ech.key")
	if err := os.MkdirAll(filepath.Dir(echKeyPath), 0o755); err != nil {
		return fmt.Errorf("create ech key dir: %w", err)
	}
	domains := []string(nil)
	if data.ACME != nil {
		domains = data.ACME.Domains
	}
	if _, err := GenerateECHKeypair(ctx.SingBoxBinary(), echServerName(data.ServerName, domains), echKeyPath); err != nil {
		return fmt.Errorf("generate ech keypair (install sing-box or pass --tuic-ech-key-path): %w", err)
	}
	data.ECHKeyPath = echKeyPath
	ctx.AddCertPath(echKeyPath)
	return ctx.SaveManifest()
}

func echServerName(serverName string, acmeDomains []string) string {
	if serverName != "" {
		return serverName
	}
	if len(acmeDomains) > 0 && acmeDomains[0] != "" {
		return acmeDomains[0]
	}
	return "localhost"
}
