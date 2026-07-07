package cmd

import (
	"github.com/spf13/cobra"

	"github.com/ivan-khludov/obscura/internal/orchestration"
)

type tuicFlagValues struct {
	orchestration.TUICCreateOptions
}

// bindTUICFlags binds CLI flags to command options.
func bindTUICFlags(cmd *cobra.Command, v *tuicFlagValues) {
	cmd.Flags().StringVar(&v.ServerName, "tuic-tls-server-name", "", "TLS server name (SNI)")
	cmd.Flags().StringSliceVar(&v.ALPN, "tuic-tls-alpn", nil, "TLS ALPN list (default: h3)")
	cmd.Flags().StringVar(&v.CertPath, "tuic-cert-path", "", "TLS certificate path (default: auto self-signed)")
	cmd.Flags().StringVar(&v.KeyPath, "tuic-key-path", "", "TLS private key path")
	cmd.Flags().StringVar(&v.MinVersion, "tuic-tls-min-version", "", "Minimum TLS version")
	cmd.Flags().StringVar(&v.MaxVersion, "tuic-tls-max-version", "", "Maximum TLS version")
	cmd.Flags().StringSliceVar(&v.CipherSuites, "tuic-tls-cipher-suites", nil, "TLS 1.0-1.2 cipher suites")
	cmd.Flags().StringSliceVar(&v.CurvePreferences, "tuic-tls-curve-preferences", nil, "TLS curve preferences")
	cmd.Flags().StringVar(&v.ClientAuthentication, "tuic-tls-client-auth", "", "TLS client authentication mode")
	cmd.Flags().StringSliceVar(&v.ClientCertificatePaths, "tuic-tls-client-cert-path", nil, "Client certificate paths")
	cmd.Flags().StringSliceVar(&v.ClientCertificatePublicKeySHA256, "tuic-tls-client-cert-pubkey-sha256", nil, "Client certificate public key SHA-256 hashes")
	cmd.Flags().BoolVar(&v.KernelTX, "tuic-tls-kernel-tx", false, "Enable kernel TLS transmit")
	cmd.Flags().BoolVar(&v.KernelRX, "tuic-tls-kernel-rx", false, "Enable kernel TLS receive")
	cmd.Flags().StringVar(&v.HandshakeTimeout, "tuic-tls-handshake-timeout", "", "TLS handshake timeout")
	cmd.Flags().StringSliceVar(&v.ACMEDomains, "tuic-acme-domain", nil, "ACME domain (repeatable)")
	cmd.Flags().StringVar(&v.ACMEEmail, "tuic-acme-email", "", "ACME account email")
	cmd.Flags().StringVar(&v.ACMEProvider, "tuic-acme-provider", "", "ACME provider")
	cmd.Flags().StringVar(&v.ACMEDataDirectory, "tuic-acme-data-directory", "", "ACME data directory")
	cmd.Flags().StringVar(&v.ACMEDefaultServerName, "tuic-acme-default-server-name", "", "ACME default server name")
	cmd.Flags().BoolVar(&v.ACMEDisableHTTPChallenge, "tuic-acme-disable-http-challenge", false, "Disable ACME HTTP challenge")
	cmd.Flags().BoolVar(&v.ACMEDisableTLSALPNChallenge, "tuic-acme-disable-tls-alpn-challenge", false, "Disable ACME TLS-ALPN challenge")
	cmd.Flags().IntVar(&v.ACMEAlternativeHTTPPort, "tuic-acme-alternative-http-port", 0, "ACME alternative HTTP port")
	cmd.Flags().IntVar(&v.ACMEAlternativeTLSPort, "tuic-acme-alternative-tls-port", 0, "ACME alternative TLS port")
	cmd.Flags().BoolVar(&v.ECH, "tuic-ech", false, "Enable TLS ECH")
	cmd.Flags().StringVar(&v.ECHKeyPath, "tuic-ech-key-path", "", "ECH key path")

	cmd.Flags().StringVar(&v.CongestionControl, "tuic-congestion-control", "", "QUIC congestion control (cubic, new_reno, bbr)")
	cmd.Flags().StringVar(&v.AuthTimeout, "tuic-auth-timeout", "", "Client authentication timeout")
	cmd.Flags().BoolVar(&v.ZeroRTTHandshake, "tuic-zero-rtt-handshake", false, "Enable 0-RTT QUIC handshake (not recommended)")
	cmd.Flags().StringVar(&v.Heartbeat, "tuic-heartbeat", "", "Heartbeat interval for keeping connections alive")

	cmd.Flags().IntVar(&v.InitialPacketSize, "tuic-initial-packet-size", 0, "Initial QUIC packet size")
	cmd.Flags().BoolVar(&v.DisablePathMTUDiscovery, "tuic-disable-path-mtu-discovery", false, "Disable QUIC path MTU discovery")
	cmd.Flags().StringVar(&v.HTTP2IdleTimeout, "tuic-http2-idle-timeout", "", "HTTP2 idle timeout")
	cmd.Flags().StringVar(&v.HTTP2KeepAlivePeriod, "tuic-http2-keep-alive-period", "", "HTTP2 keep alive period")
	cmd.Flags().StringVar(&v.HTTP2StreamReceiveWindow, "tuic-http2-stream-receive-window", "", "HTTP2 stream receive window")
	cmd.Flags().StringVar(&v.HTTP2ConnectionReceiveWindow, "tuic-http2-connection-receive-window", "", "HTTP2 connection receive window")
	cmd.Flags().IntVar(&v.HTTP2MaxConcurrentStreams, "tuic-http2-max-concurrent-streams", 0, "HTTP2 max concurrent streams")
}

// readTUICInput performs an internal helper operation.
func readTUICInput(v tuicFlagValues) orchestration.TUICCreateOptions {
	return v.TUICCreateOptions
}
