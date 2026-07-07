package trojan

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/ivan-khludov/obscura/internal/certs"
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/protocol/inbound"
)

const (
	previewCertPath          = "/preview/obscura.crt"
	previewKeyPath           = "/preview/obscura.key"
	previewECHKeyPath        = "/preview/obscura-ech.key"
	previewRealityPrivateKey = "preview-reality-private-key"
	previewRealityShortID    = "abcd"
)

// CreateOptions holds Trojan-specific create parameters.
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
	Reality                          bool
	RealityHandshake                 string
	RealityHandshakePort             int
	RealityPrivateKey                string
	RealityShortIDs                  []string
	RealityMaxTimeDifference         string
	RealityUTLSFingerprint           string
	ECH                              bool
	ECHKeyPath                       string
	FallbackServer                   string
	FallbackPort                     int
	FallbackForALPNJSON              string
	Multiplex                        bool
	MultiplexPadding                 bool
	Transport                        string
	TransportPath                    string
	TransportHost                    string
	TransportHosts                   []string
	TransportServiceName             string
	TransportMethod                  string
	TransportHeadersJSON             string
	WSMaxEarlyData                   int
	WSEarlyDataHeaderName            string
	GRPCPermitWithoutStream          bool
}

// BuildProtocolData builds and validates Trojan protocol data.
func (a *Adapter) BuildProtocolData(ctx protocol.BuildContext, spec domain.CreateVPNSpec, tag string, mode protocol.BuildMode) ([]byte, error) {
	opts, err := createOptionsFromSpec(spec)
	if err != nil {
		return nil, err
	}
	data, err := buildCreateProtocolData(ctx.ServerHost(), opts)
	if err != nil {
		return nil, err
	}
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

// NeedsInitialClient reports whether Trojan requires an enabled client.
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
		return CreateOptions{}, fmt.Errorf("trojan create options have unexpected type %T", spec.ProtocolOptions)
	}
}

func buildCreateProtocolData(serverHost string, t CreateOptions) (ProtocolData, error) {
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
		RealityEnabled:                   t.Reality,
		RealityPrivateKey:                t.RealityPrivateKey,
		RealityShortIDs:                  t.RealityShortIDs,
		RealityHandshakeServer:           t.RealityHandshake,
		RealityHandshakePort:             t.RealityHandshakePort,
		RealityMaxTimeDifference:         t.RealityMaxTimeDifference,
		ECHEnabled:                       t.ECH,
		ECHKeyPath:                       t.ECHKeyPath,
		FallbackServer:                   t.FallbackServer,
		FallbackPort:                     t.FallbackPort,
		Multiplex:                        t.Multiplex,
		MultiplexPadding:                 t.MultiplexPadding,
		TransportType:                    t.Transport,
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
	if t.FallbackForALPNJSON != "" {
		var fallbackForALPN map[string]FallbackTarget
		if err := json.Unmarshal([]byte(t.FallbackForALPNJSON), &fallbackForALPN); err != nil {
			return data, fmt.Errorf("parse fallback_for_alpn json: %w", err)
		}
		data.FallbackForALPN = fallbackForALPN
	}
	if err := applyTransport(&data, t); err != nil {
		return data, err
	}
	data.ALPN = inbound.ALPNForTransport(data.TransportType, data.ALPN)
	fp, err := resolveRealityUTLSFingerprint(data.RealityEnabled, t.RealityUTLSFingerprint)
	if err != nil {
		return data, err
	}
	data.RealityUTLSFingerprint = fp
	return data, nil
}

func applyPreviewTLS(data *ProtocolData, t CreateOptions) {
	if t.Reality {
		if data.RealityHandshakeServer == "" {
			data.RealityHandshakeServer = data.ServerName
		}
		if data.RealityPrivateKey == "" {
			data.RealityPrivateKey = previewRealityPrivateKey
		}
		if len(data.RealityShortIDs) == 0 {
			data.RealityShortIDs = []string{previewRealityShortID}
		}
		return
	}
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

func applyTransport(data *ProtocolData, t CreateOptions) error {
	var headers map[string]string
	if t.TransportHeadersJSON != "" {
		if err := json.Unmarshal([]byte(t.TransportHeadersJSON), &headers); err != nil {
			return fmt.Errorf("parse transport headers json: %w", err)
		}
	}
	switch t.Transport {
	case "", "tcp":
		data.TransportType = ""
	case "quic":
		data.TransportType = "quic"
	case "http":
		hosts := t.TransportHosts
		if len(hosts) == 0 && t.TransportHost != "" {
			hosts = []string{t.TransportHost}
		}
		data.TransportType = "http"
		data.TransportHTTP = &TransportHTTP{
			Host: hosts, Path: t.TransportPath, Method: t.TransportMethod, Headers: headers,
		}
	case "ws":
		data.TransportType = "ws"
		data.TransportWS = &TransportWS{
			Path: t.TransportPath, Headers: headers,
			MaxEarlyData: t.WSMaxEarlyData, EarlyDataHeaderName: t.WSEarlyDataHeaderName,
		}
	case "grpc":
		data.TransportType = "grpc"
		data.TransportGRPC = &TransportGRPC{
			ServiceName: t.TransportServiceName, PermitWithoutStream: t.GRPCPermitWithoutStream,
		}
	case "httpupgrade":
		data.TransportType = "httpupgrade"
		data.TransportHTTPUpgrade = &TransportHTTPUpgrade{
			Host: t.TransportHost, Path: t.TransportPath, Headers: headers,
		}
	default:
		return fmt.Errorf("unsupported trojan transport %q", t.Transport)
	}
	return nil
}

func setupTLS(ctx protocol.BuildContext, data *ProtocolData, tag string, t CreateOptions) error {
	if t.Reality {
		if data.RealityHandshakeServer == "" {
			data.RealityHandshakeServer = data.ServerName
		}
		if data.RealityPrivateKey == "" {
			pair, err := GenerateRealityKeypair(ctx.SingBoxBinary())
			if err != nil {
				return fmt.Errorf("generate reality keypair (install sing-box or pass --reality-private-key): %w", err)
			}
			data.RealityPrivateKey = pair.PrivateKey
			data.RealityPublicKey = pair.PublicKey
		}
		if len(data.RealityShortIDs) == 0 {
			shortID, err := GenerateRealityShortID()
			if err != nil {
				return err
			}
			data.RealityShortIDs = []string{shortID}
		}
		return nil
	}
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
	domains := []string(nil)
	if data.ACME != nil {
		domains = data.ACME.Domains
	}
	if _, err := GenerateECHKeypair(ctx.SingBoxBinary(), echServerName(data.ServerName, domains), echKeyPath); err != nil {
		return fmt.Errorf("generate ech keypair (install sing-box or pass --ech-key-path): %w", err)
	}
	data.ECHKeyPath = echKeyPath
	ctx.AddCertPath(echKeyPath)
	return ctx.SaveManifest()
}

func resolveRealityUTLSFingerprint(reality bool, fp string) (string, error) {
	if fp != "" && !reality {
		return "", fmt.Errorf("reality fingerprint requires reality to be enabled")
	}
	if fp != "" {
		if err := protocol.ValidateRealityUTLSFingerprint(fp); err != nil {
			return "", err
		}
		return fp, nil
	}
	if reality {
		return protocol.DefaultRealityShareLinkFingerprint, nil
	}
	return "", nil
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
