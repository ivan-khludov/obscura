package cmd

import (
	"github.com/spf13/cobra"

	"github.com/ivan-khludov/obscura/internal/orchestration"
)

type trojanFlagValues struct {
	orchestration.TrojanCreateOptions
}

// bindTrojanFlags binds CLI flags to command options.
func bindTrojanFlags(cmd *cobra.Command, v *trojanFlagValues) {
	cmd.Flags().StringVar(&v.ServerName, "tls-server-name", "", "TLS server name (SNI)")
	cmd.Flags().StringSliceVar(&v.ALPN, "tls-alpn", nil, "TLS ALPN list")
	cmd.Flags().StringVar(&v.CertPath, "cert-path", "", "TLS certificate path (default: auto self-signed)")
	cmd.Flags().StringVar(&v.KeyPath, "key-path", "", "TLS private key path")
	cmd.Flags().StringVar(&v.MinVersion, "tls-min-version", "", "Minimum TLS version")
	cmd.Flags().StringVar(&v.MaxVersion, "tls-max-version", "", "Maximum TLS version")
	cmd.Flags().StringSliceVar(&v.CipherSuites, "tls-cipher-suites", nil, "TLS 1.0-1.2 cipher suites")
	cmd.Flags().StringSliceVar(&v.CurvePreferences, "tls-curve-preferences", nil, "TLS curve preferences")
	cmd.Flags().StringVar(&v.ClientAuthentication, "tls-client-auth", "", "TLS client authentication mode")
	cmd.Flags().StringSliceVar(&v.ClientCertificatePaths, "tls-client-cert-path", nil, "Client certificate paths")
	cmd.Flags().StringSliceVar(&v.ClientCertificatePublicKeySHA256, "tls-client-cert-pubkey-sha256", nil, "Client certificate public key SHA-256 hashes")
	cmd.Flags().BoolVar(&v.KernelTX, "tls-kernel-tx", false, "Enable kernel TLS transmit")
	cmd.Flags().BoolVar(&v.KernelRX, "tls-kernel-rx", false, "Enable kernel TLS receive")
	cmd.Flags().StringVar(&v.HandshakeTimeout, "tls-handshake-timeout", "", "TLS handshake timeout")
	cmd.Flags().StringSliceVar(&v.ACMEDomains, "acme-domain", nil, "ACME domain (repeatable)")
	cmd.Flags().StringVar(&v.ACMEEmail, "acme-email", "", "ACME account email")
	cmd.Flags().StringVar(&v.ACMEProvider, "acme-provider", "", "ACME provider")
	cmd.Flags().StringVar(&v.ACMEDataDirectory, "acme-data-directory", "", "ACME data directory")
	cmd.Flags().StringVar(&v.ACMEDefaultServerName, "acme-default-server-name", "", "ACME default server name")
	cmd.Flags().BoolVar(&v.ACMEDisableHTTPChallenge, "acme-disable-http-challenge", false, "Disable ACME HTTP challenge")
	cmd.Flags().BoolVar(&v.ACMEDisableTLSALPNChallenge, "acme-disable-tls-alpn-challenge", false, "Disable ACME TLS-ALPN challenge")
	cmd.Flags().IntVar(&v.ACMEAlternativeHTTPPort, "acme-alternative-http-port", 0, "ACME alternative HTTP port")
	cmd.Flags().IntVar(&v.ACMEAlternativeTLSPort, "acme-alternative-tls-port", 0, "ACME alternative TLS port")
	cmd.Flags().BoolVar(&v.Reality, "reality", false, "Enable TLS Reality")
	cmd.Flags().StringVar(&v.RealityHandshake, "reality-handshake", "", "Reality handshake server")
	cmd.Flags().IntVar(&v.RealityHandshakePort, "reality-handshake-port", 0, "Reality handshake port")
	cmd.Flags().StringVar(&v.RealityPrivateKey, "reality-private-key", "", "Reality private key")
	cmd.Flags().StringSliceVar(&v.RealityShortIDs, "reality-short-id", nil, "Reality short_id (repeatable)")
	cmd.Flags().StringVar(&v.RealityMaxTimeDifference, "reality-max-time-difference", "", "Reality max time difference")
	cmd.Flags().StringVar(&v.RealityUTLSFingerprint, "reality-fingerprint", "", "uTLS fingerprint for Reality share links (default: chrome)")
	cmd.Flags().BoolVar(&v.ECH, "ech", false, "Enable TLS ECH")
	cmd.Flags().StringVar(&v.ECHKeyPath, "ech-key-path", "", "ECH key path")
	cmd.Flags().StringVar(&v.FallbackServer, "fallback-server", "", "Fallback server address")
	cmd.Flags().IntVar(&v.FallbackPort, "fallback-port", 0, "Fallback server port")
	cmd.Flags().StringVar(&v.FallbackForALPNJSON, "fallback-for-alpn", "", "Fallback-for-ALPN JSON object")
	cmd.Flags().StringVar(&v.Transport, "transport", "", "V2Ray transport (ws, grpc, http, httpupgrade, quic)")
	cmd.Flags().StringVar(&v.TransportPath, "transport-path", "", "Transport path")
	cmd.Flags().StringVar(&v.TransportHost, "transport-host", "", "Transport host")
	cmd.Flags().StringSliceVar(&v.TransportHosts, "transport-hosts", nil, "HTTP transport host list")
	cmd.Flags().StringVar(&v.TransportServiceName, "transport-service-name", "", "gRPC service name")
	cmd.Flags().StringVar(&v.TransportMethod, "transport-method", "", "HTTP transport method")
	cmd.Flags().StringVar(&v.TransportHeadersJSON, "transport-headers", "", "Transport headers JSON object")
	cmd.Flags().IntVar(&v.WSMaxEarlyData, "ws-max-early-data", 0, "WebSocket max early data")
	cmd.Flags().StringVar(&v.WSEarlyDataHeaderName, "ws-early-data-header-name", "", "WebSocket early data header name")
	cmd.Flags().BoolVar(&v.GRPCPermitWithoutStream, "grpc-permit-without-stream", false, "gRPC permit without stream")
}

// readTrojanInput performs an internal helper operation.
func readTrojanInput(v trojanFlagValues, multiplex, multiplexPadding bool) orchestration.TrojanCreateOptions {
	return orchestration.BuildTrojanCreateOptions(v.TrojanCreateOptions, multiplex, multiplexPadding, false)
}

// applyFallbackStub applies transport, TLS preview, or option fields to protocol data.
func applyFallbackStub(v *trojanFlagValues, stub bool) {
	v.TrojanCreateOptions = orchestration.BuildTrojanCreateOptions(v.TrojanCreateOptions, v.Multiplex, v.MultiplexPadding, stub)
}
