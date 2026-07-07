package inbound

// TLSCoreParams carries the TLS inbound fields shared by all TLS-based
// protocol adapters (trojan, vmess, vless, hysteria2, tuic).
type TLSCoreParams struct {
	ServerName                       string
	ALPN                             []string
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
	CertPath                         string
	KeyPath                          string
	ACME                             *ACMEOptions
	ECHEnabled                       bool
	ECHKeyPath                       string

	// RealityEnabled overrides ServerName with RealityHandshakeServer (when
	// set) and, when Reality is non-nil, renders the "reality" fragment.
	RealityEnabled         bool
	RealityHandshakeServer string
	Reality                *RealityParams
}

// RenderTLSCore builds the common sing-box "tls" fragment shared by all
// TLS-based inbound protocols.
func RenderTLSCore(p TLSCoreParams) map[string]any {
	tls := map[string]any{"enabled": true}
	serverName := p.ServerName
	if p.RealityEnabled && p.RealityHandshakeServer != "" {
		serverName = p.RealityHandshakeServer
	}
	if serverName != "" {
		tls["server_name"] = serverName
	}
	if len(p.ALPN) > 0 {
		tls["alpn"] = p.ALPN
	}
	if p.MinVersion != "" {
		tls["min_version"] = p.MinVersion
	}
	if p.MaxVersion != "" {
		tls["max_version"] = p.MaxVersion
	}
	if len(p.CipherSuites) > 0 {
		tls["cipher_suites"] = p.CipherSuites
	}
	if len(p.CurvePreferences) > 0 {
		tls["curve_preferences"] = p.CurvePreferences
	}
	if p.ClientAuthentication != "" {
		tls["client_authentication"] = p.ClientAuthentication
	}
	if len(p.ClientCertificatePaths) > 0 {
		tls["client_certificate_path"] = p.ClientCertificatePaths
	}
	if len(p.ClientCertificatePublicKeySHA256) > 0 {
		tls["client_certificate_public_key_sha256"] = p.ClientCertificatePublicKeySHA256
	}
	if p.KernelTX {
		tls["kernel_tx"] = true
	}
	if p.KernelRX {
		tls["kernel_rx"] = true
	}
	if p.HandshakeTimeout != "" {
		tls["handshake_timeout"] = p.HandshakeTimeout
	}
	if p.CertPath != "" {
		tls["certificate_path"] = p.CertPath
	}
	if p.KeyPath != "" {
		tls["key_path"] = p.KeyPath
	}
	if p.ACME != nil && len(p.ACME.Domains) > 0 {
		tls["acme"] = RenderACME(*p.ACME)
	}
	if p.ECHEnabled {
		ech := map[string]any{"enabled": true}
		if p.ECHKeyPath != "" {
			ech["key_path"] = p.ECHKeyPath
		}
		tls["ech"] = ech
	}
	if p.RealityEnabled && p.Reality != nil {
		tls["reality"] = RenderReality(*p.Reality)
	}
	return tls
}
