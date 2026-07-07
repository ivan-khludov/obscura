package vmess

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

// CreateOptions holds VMess-specific create parameters.
type CreateOptions struct {
	DefaultAlterId                   int
	NoTLS                            bool
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
	MultiplexBrutal                  bool
	MultiplexBrutalUpMbps            int
	MultiplexBrutalDownMbps          int
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

// BuildProtocolData builds and validates VMess protocol data.
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
		if !data.TLSDisabled {
			applyPreviewTLS(&data, opts)
		}
	case protocol.BuildModeProvision:
		if !data.TLSDisabled {
			if err := setupTLS(ctx, &data, tag, opts); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("unknown build mode %d", mode)
	}
	if err := ValidateOptions(data); err != nil {
		return nil, err
	}
	return MarshalProtocolData(data)
}

// NeedsInitialClient reports whether VMess requires an enabled client.
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
		return CreateOptions{}, fmt.Errorf("vmess create options have unexpected type %T", spec.ProtocolOptions)
	}
}

func buildCreateProtocolData(serverHost string, v CreateOptions) (ProtocolData, error) {
	data := ProtocolData{
		TLSDisabled:                      v.NoTLS,
		DefaultAlterId:                   v.DefaultAlterId,
		ServerName:                       v.ServerName,
		ALPN:                             v.ALPN,
		CertPath:                         v.CertPath,
		KeyPath:                          v.KeyPath,
		MinVersion:                       v.MinVersion,
		MaxVersion:                       v.MaxVersion,
		CipherSuites:                     v.CipherSuites,
		CurvePreferences:                 v.CurvePreferences,
		ClientAuthentication:             v.ClientAuthentication,
		ClientCertificatePaths:           v.ClientCertificatePaths,
		ClientCertificatePublicKeySHA256: v.ClientCertificatePublicKeySHA256,
		KernelTX:                         v.KernelTX,
		KernelRX:                         v.KernelRX,
		HandshakeTimeout:                 v.HandshakeTimeout,
		RealityEnabled:                   v.Reality,
		RealityPrivateKey:                v.RealityPrivateKey,
		RealityShortIDs:                  v.RealityShortIDs,
		RealityHandshakeServer:           v.RealityHandshake,
		RealityHandshakePort:             v.RealityHandshakePort,
		RealityMaxTimeDifference:         v.RealityMaxTimeDifference,
		ECHEnabled:                       v.ECH,
		ECHKeyPath:                       v.ECHKeyPath,
		FallbackServer:                   v.FallbackServer,
		FallbackPort:                     v.FallbackPort,
		Multiplex:                        v.Multiplex,
		MultiplexPadding:                 v.MultiplexPadding,
		MultiplexBrutal:                  v.MultiplexBrutal,
		MultiplexBrutalUpMbps:            v.MultiplexBrutalUpMbps,
		MultiplexBrutalDownMbps:          v.MultiplexBrutalDownMbps,
		TransportType:                    v.Transport,
	}
	if !data.TLSDisabled {
		if data.ServerName == "" {
			data.ServerName = serverHost
		}
		if len(data.ALPN) == 0 {
			data.ALPN = append([]string{}, DefaultALPN...)
		}
	}
	if len(v.ACMEDomains) > 0 {
		data.ACME = &ACMEOptions{
			Domains:                 v.ACMEDomains,
			Email:                   v.ACMEEmail,
			Provider:                v.ACMEProvider,
			DataDirectory:           v.ACMEDataDirectory,
			DefaultServerName:       v.ACMEDefaultServerName,
			DisableHTTPChallenge:    v.ACMEDisableHTTPChallenge,
			DisableTLSALPNChallenge: v.ACMEDisableTLSALPNChallenge,
			AlternativeHTTPPort:     v.ACMEAlternativeHTTPPort,
			AlternativeTLSPort:      v.ACMEAlternativeTLSPort,
		}
	}
	if v.FallbackForALPNJSON != "" {
		var fallbackForALPN map[string]FallbackTarget
		if err := json.Unmarshal([]byte(v.FallbackForALPNJSON), &fallbackForALPN); err != nil {
			return data, fmt.Errorf("parse fallback_for_alpn json: %w", err)
		}
		data.FallbackForALPN = fallbackForALPN
	}
	if err := applyTransport(&data, v); err != nil {
		return data, err
	}
	data.ALPN = inbound.ALPNForTransport(data.TransportType, data.ALPN)
	fp, err := resolveRealityUTLSFingerprint(data.RealityEnabled, v.RealityUTLSFingerprint)
	if err != nil {
		return data, err
	}
	data.RealityUTLSFingerprint = fp
	return data, nil
}

func applyPreviewTLS(data *ProtocolData, v CreateOptions) {
	if v.Reality {
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
		if v.ECH && data.ECHKeyPath == "" {
			data.ECHEnabled = true
			data.ECHKeyPath = previewECHKeyPath
		}
		return
	}
	if data.CertPath != "" && data.KeyPath != "" {
		if v.ECH && data.ECHKeyPath == "" {
			data.ECHEnabled = true
			data.ECHKeyPath = previewECHKeyPath
		}
		return
	}
	data.CertPath = previewCertPath
	data.KeyPath = previewKeyPath
	if v.ECH {
		data.ECHEnabled = true
		data.ECHKeyPath = previewECHKeyPath
	}
}

func applyTransport(data *ProtocolData, v CreateOptions) error {
	var headers map[string]string
	if v.TransportHeadersJSON != "" {
		if err := json.Unmarshal([]byte(v.TransportHeadersJSON), &headers); err != nil {
			return fmt.Errorf("parse transport headers json: %w", err)
		}
	}
	switch v.Transport {
	case "", "tcp":
		data.TransportType = ""
	case "quic":
		data.TransportType = "quic"
	case "http":
		hosts := v.TransportHosts
		if len(hosts) == 0 && v.TransportHost != "" {
			hosts = []string{v.TransportHost}
		}
		data.TransportType = "http"
		data.TransportHTTP = &TransportHTTP{
			Host: hosts, Path: v.TransportPath, Method: v.TransportMethod, Headers: headers,
		}
	case "ws":
		data.TransportType = "ws"
		data.TransportWS = &TransportWS{
			Path: v.TransportPath, Headers: headers,
			MaxEarlyData: v.WSMaxEarlyData, EarlyDataHeaderName: v.WSEarlyDataHeaderName,
		}
	case "grpc":
		data.TransportType = "grpc"
		data.TransportGRPC = &TransportGRPC{
			ServiceName: v.TransportServiceName, PermitWithoutStream: v.GRPCPermitWithoutStream,
		}
	case "httpupgrade":
		data.TransportType = "httpupgrade"
		data.TransportHTTPUpgrade = &TransportHTTPUpgrade{
			Host: v.TransportHost, Path: v.TransportPath, Headers: headers,
		}
	default:
		return fmt.Errorf("unsupported vmess transport %q", v.Transport)
	}
	return nil
}

func setupTLS(ctx protocol.BuildContext, data *ProtocolData, tag string, v CreateOptions) error {
	if v.Reality {
		if data.RealityHandshakeServer == "" {
			data.RealityHandshakeServer = data.ServerName
		}
		if data.RealityPrivateKey == "" {
			pair, err := tlsGenFactory().GenerateRealityKeypair(ctx.SingBoxBinary())
			if err != nil {
				return fmt.Errorf("generate reality keypair (install sing-box or pass --reality-private-key): %w", err)
			}
			data.RealityPrivateKey = pair.PrivateKey
		}
		if len(data.RealityShortIDs) == 0 {
			shortID, err := tlsGenFactory().GenerateRealityShortID()
			if err != nil {
				return err
			}
			data.RealityShortIDs = []string{shortID}
		}
		return nil
	}
	if data.ACME != nil && len(data.ACME.Domains) > 0 {
		if v.ECH {
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
		if v.ECH {
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
	if v.ECH {
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
	if _, err := tlsGenFactory().GenerateECHKeypair(ctx.SingBoxBinary(), echServerName(data.ServerName, domains), echKeyPath); err != nil {
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
