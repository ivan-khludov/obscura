package hysteria2

import (
	"encoding/json"
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

// CreateOptions holds Hysteria2-specific create parameters.
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
	UpMbps                           int
	DownMbps                         int
	IgnoreClientBandwidth            bool
	ObfsPassword                     string
	MasqueradeURL                    string
	MasqueradeType                   string
	MasqueradeDirectory              string
	MasqueradeProxyURL               string
	MasqueradeRewriteHost            bool
	MasqueradeStatusCode             int
	MasqueradeHeadersJSON            string
	MasqueradeContent                string
	BrutalDebug                      bool
	BBRProfile                       string
	InitialPacketSize                int
	DisablePathMTUDiscovery          bool
	HTTP2IdleTimeout                 string
	HTTP2KeepAlivePeriod             string
	HTTP2StreamReceiveWindow         string
	HTTP2ConnectionReceiveWindow     string
	HTTP2MaxConcurrentStreams        int
	RealmServerURL                   string
	RealmToken                       string
	RealmID                          string
	RealmSTUNServers                 []string
	RealmSTUNDomainResolver          string
	RealmHTTPClientJSON              string
}

// BuildProtocolData builds and validates Hysteria2 protocol data.
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
		if data.ObfsPassword == "auto" {
			data.ObfsPassword = "preview-obfs-password"
		}
		applyPreviewTLS(&data, opts)
	case protocol.BuildModeProvision:
		if data.ObfsPassword == "auto" {
			password, err := ctx.GeneratePassword(16)
			if err != nil {
				return nil, fmt.Errorf("generate obfs password: %w", err)
			}
			data.ObfsPassword = password
		}
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

// NeedsInitialClient reports whether Hysteria2 requires an enabled client.
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
		return CreateOptions{}, fmt.Errorf("hysteria2 create options have unexpected type %T", spec.ProtocolOptions)
	}
}

func buildCreateProtocolData(serverHost string, h CreateOptions) (ProtocolData, error) {
	data := ProtocolData{
		ServerName:                       h.ServerName,
		ALPN:                             h.ALPN,
		CertPath:                         h.CertPath,
		KeyPath:                          h.KeyPath,
		MinVersion:                       h.MinVersion,
		MaxVersion:                       h.MaxVersion,
		CipherSuites:                     h.CipherSuites,
		CurvePreferences:                 h.CurvePreferences,
		ClientAuthentication:             h.ClientAuthentication,
		ClientCertificatePaths:           h.ClientCertificatePaths,
		ClientCertificatePublicKeySHA256: h.ClientCertificatePublicKeySHA256,
		KernelTX:                         h.KernelTX,
		KernelRX:                         h.KernelRX,
		HandshakeTimeout:                 h.HandshakeTimeout,
		ECHEnabled:                       h.ECH,
		ECHKeyPath:                       h.ECHKeyPath,
		UpMbps:                           h.UpMbps,
		DownMbps:                         h.DownMbps,
		IgnoreClientBandwidth:            h.IgnoreClientBandwidth,
		ObfsPassword:                     h.ObfsPassword,
		MasqueradeURL:                    h.MasqueradeURL,
		BrutalDebug:                      h.BrutalDebug,
		BBRProfile:                       h.BBRProfile,
		InitialPacketSize:                h.InitialPacketSize,
		DisablePathMTUDiscovery:          h.DisablePathMTUDiscovery,
	}
	if data.ServerName == "" {
		data.ServerName = serverHost
	}
	if len(data.ALPN) == 0 {
		data.ALPN = append([]string{}, DefaultALPN...)
	}
	if len(h.ACMEDomains) > 0 {
		data.ACME = &ACMEOptions{
			Domains:                 h.ACMEDomains,
			Email:                   h.ACMEEmail,
			Provider:                h.ACMEProvider,
			DataDirectory:           h.ACMEDataDirectory,
			DefaultServerName:       h.ACMEDefaultServerName,
			DisableHTTPChallenge:    h.ACMEDisableHTTPChallenge,
			DisableTLSALPNChallenge: h.ACMEDisableTLSALPNChallenge,
			AlternativeHTTPPort:     h.ACMEAlternativeHTTPPort,
			AlternativeTLSPort:      h.ACMEAlternativeTLSPort,
		}
	}
	if h.MasqueradeType != "" {
		masq, err := buildMasqueradeObject(h)
		if err != nil {
			return data, err
		}
		data.Masquerade = masq
	}
	if h.HTTP2IdleTimeout != "" || h.HTTP2KeepAlivePeriod != "" ||
		h.HTTP2StreamReceiveWindow != "" || h.HTTP2ConnectionReceiveWindow != "" ||
		h.HTTP2MaxConcurrentStreams > 0 {
		data.HTTP2 = &HTTP2Options{
			IdleTimeout:             h.HTTP2IdleTimeout,
			KeepAlivePeriod:         h.HTTP2KeepAlivePeriod,
			StreamReceiveWindow:     h.HTTP2StreamReceiveWindow,
			ConnectionReceiveWindow: h.HTTP2ConnectionReceiveWindow,
			MaxConcurrentStreams:    h.HTTP2MaxConcurrentStreams,
		}
	}
	if h.RealmServerURL != "" || h.RealmID != "" || len(h.RealmSTUNServers) > 0 {
		realm := &RealmOptions{
			ServerURL:   h.RealmServerURL,
			Token:       h.RealmToken,
			RealmID:     h.RealmID,
			STUNServers: h.RealmSTUNServers,
		}
		if h.RealmSTUNDomainResolver != "" {
			raw := h.RealmSTUNDomainResolver
			if !json.Valid([]byte(raw)) {
				raw = fmt.Sprintf("%q", raw)
			}
			realm.STUNDomainResolver = json.RawMessage(raw)
		}
		if h.RealmHTTPClientJSON != "" {
			realm.HTTPClient = json.RawMessage(h.RealmHTTPClientJSON)
		}
		data.Realm = realm
	}
	return data, nil
}

func buildMasqueradeObject(h CreateOptions) (*MasqueradeObject, error) {
	m := &MasqueradeObject{Type: h.MasqueradeType}
	switch h.MasqueradeType {
	case MasqueradeTypeFile:
		m.Directory = h.MasqueradeDirectory
	case MasqueradeTypeProxy:
		m.URL = h.MasqueradeProxyURL
		m.RewriteHost = h.MasqueradeRewriteHost
	case MasqueradeTypeString:
		m.StatusCode = h.MasqueradeStatusCode
		m.Content = h.MasqueradeContent
		if h.MasqueradeHeadersJSON != "" {
			var headers map[string]string
			if err := json.Unmarshal([]byte(h.MasqueradeHeadersJSON), &headers); err != nil {
				return nil, fmt.Errorf("parse masquerade headers json: %w", err)
			}
			m.Headers = headers
		}
	}
	return m, nil
}

func applyPreviewTLS(data *ProtocolData, h CreateOptions) {
	if data.ACME != nil && len(data.ACME.Domains) > 0 {
		if h.ECH && data.ECHKeyPath == "" {
			data.ECHEnabled = true
			data.ECHKeyPath = previewECHKeyPath
		}
		return
	}
	if data.CertPath != "" && data.KeyPath != "" {
		if h.ECH && data.ECHKeyPath == "" {
			data.ECHEnabled = true
			data.ECHKeyPath = previewECHKeyPath
		}
		return
	}
	data.CertPath = previewCertPath
	data.KeyPath = previewKeyPath
	if h.ECH {
		data.ECHEnabled = true
		data.ECHKeyPath = previewECHKeyPath
	}
}

func setupTLS(ctx protocol.BuildContext, data *ProtocolData, tag string, h CreateOptions) error {
	if data.ACME != nil && len(data.ACME.Domains) > 0 {
		if h.ECH {
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
		if h.ECH {
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
	if h.ECH {
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
		return fmt.Errorf("generate ech keypair (install sing-box or pass --hy2-ech-key-path): %w", err)
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
