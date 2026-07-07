package cmd

import (
	"github.com/spf13/cobra"

	"github.com/ivan-khludov/obscura/internal/orchestration"
)

type hysteria2FlagValues struct {
	orchestration.Hysteria2CreateOptions
}

// bindHysteria2Flags binds CLI flags to command options.
func bindHysteria2Flags(cmd *cobra.Command, v *hysteria2FlagValues) {
	cmd.Flags().StringVar(&v.ServerName, "hy2-tls-server-name", "", "TLS server name (SNI)")
	cmd.Flags().StringSliceVar(&v.ALPN, "hy2-tls-alpn", nil, "TLS ALPN list (default: h3)")
	cmd.Flags().StringVar(&v.CertPath, "hy2-cert-path", "", "TLS certificate path (default: auto self-signed)")
	cmd.Flags().StringVar(&v.KeyPath, "hy2-key-path", "", "TLS private key path")
	cmd.Flags().StringVar(&v.MinVersion, "hy2-tls-min-version", "", "Minimum TLS version")
	cmd.Flags().StringVar(&v.MaxVersion, "hy2-tls-max-version", "", "Maximum TLS version")
	cmd.Flags().StringSliceVar(&v.CipherSuites, "hy2-tls-cipher-suites", nil, "TLS 1.0-1.2 cipher suites")
	cmd.Flags().StringSliceVar(&v.CurvePreferences, "hy2-tls-curve-preferences", nil, "TLS curve preferences")
	cmd.Flags().StringVar(&v.ClientAuthentication, "hy2-tls-client-auth", "", "TLS client authentication mode")
	cmd.Flags().StringSliceVar(&v.ClientCertificatePaths, "hy2-tls-client-cert-path", nil, "Client certificate paths")
	cmd.Flags().StringSliceVar(&v.ClientCertificatePublicKeySHA256, "hy2-tls-client-cert-pubkey-sha256", nil, "Client certificate public key SHA-256 hashes")
	cmd.Flags().BoolVar(&v.KernelTX, "hy2-tls-kernel-tx", false, "Enable kernel TLS transmit")
	cmd.Flags().BoolVar(&v.KernelRX, "hy2-tls-kernel-rx", false, "Enable kernel TLS receive")
	cmd.Flags().StringVar(&v.HandshakeTimeout, "hy2-tls-handshake-timeout", "", "TLS handshake timeout")
	cmd.Flags().StringSliceVar(&v.ACMEDomains, "hy2-acme-domain", nil, "ACME domain (repeatable)")
	cmd.Flags().StringVar(&v.ACMEEmail, "hy2-acme-email", "", "ACME account email")
	cmd.Flags().StringVar(&v.ACMEProvider, "hy2-acme-provider", "", "ACME provider")
	cmd.Flags().StringVar(&v.ACMEDataDirectory, "hy2-acme-data-directory", "", "ACME data directory")
	cmd.Flags().StringVar(&v.ACMEDefaultServerName, "hy2-acme-default-server-name", "", "ACME default server name")
	cmd.Flags().BoolVar(&v.ACMEDisableHTTPChallenge, "hy2-acme-disable-http-challenge", false, "Disable ACME HTTP challenge")
	cmd.Flags().BoolVar(&v.ACMEDisableTLSALPNChallenge, "hy2-acme-disable-tls-alpn-challenge", false, "Disable ACME TLS-ALPN challenge")
	cmd.Flags().IntVar(&v.ACMEAlternativeHTTPPort, "hy2-acme-alternative-http-port", 0, "ACME alternative HTTP port")
	cmd.Flags().IntVar(&v.ACMEAlternativeTLSPort, "hy2-acme-alternative-tls-port", 0, "ACME alternative TLS port")
	cmd.Flags().BoolVar(&v.ECH, "hy2-ech", false, "Enable TLS ECH")
	cmd.Flags().StringVar(&v.ECHKeyPath, "hy2-ech-key-path", "", "ECH key path")

	cmd.Flags().IntVar(&v.UpMbps, "hy2-up-mbps", 0, "Server uplink bandwidth in Mbps (Brutal CC)")
	cmd.Flags().IntVar(&v.DownMbps, "hy2-down-mbps", 0, "Server downlink bandwidth in Mbps (Brutal CC)")
	cmd.Flags().BoolVar(&v.IgnoreClientBandwidth, "hy2-ignore-client-bandwidth", false, "Force clients to use BBR instead of Brutal CC")
	cmd.Flags().StringVar(&v.ObfsPassword, "hy2-obfs-password", "", "Salamander obfuscation password")
	cmd.Flags().BoolVar(&v.BrutalDebug, "hy2-brutal-debug", false, "Enable Brutal CC debug logging")
	cmd.Flags().StringVar(&v.BBRProfile, "hy2-bbr-profile", "", "BBR profile (conservative, standard, aggressive)")

	cmd.Flags().StringVar(&v.MasqueradeURL, "hy2-masquerade", "", "Masquerade URL (file:// or http(s)://)")
	cmd.Flags().StringVar(&v.MasqueradeType, "hy2-masquerade-type", "", "Masquerade object type (file, proxy, string)")
	cmd.Flags().StringVar(&v.MasqueradeDirectory, "hy2-masquerade-directory", "", "Masquerade file server root directory")
	cmd.Flags().StringVar(&v.MasqueradeProxyURL, "hy2-masquerade-url", "", "Masquerade reverse proxy target URL")
	cmd.Flags().BoolVar(&v.MasqueradeRewriteHost, "hy2-masquerade-rewrite-host", false, "Rewrite Host header for masquerade proxy")
	cmd.Flags().IntVar(&v.MasqueradeStatusCode, "hy2-masquerade-status-code", 0, "Masquerade fixed response status code")
	cmd.Flags().StringVar(&v.MasqueradeHeadersJSON, "hy2-masquerade-headers", "", "Masquerade fixed response headers JSON")
	cmd.Flags().StringVar(&v.MasqueradeContent, "hy2-masquerade-content", "", "Masquerade fixed response content")

	cmd.Flags().IntVar(&v.InitialPacketSize, "hy2-initial-packet-size", 0, "Initial QUIC packet size")
	cmd.Flags().BoolVar(&v.DisablePathMTUDiscovery, "hy2-disable-path-mtu-discovery", false, "Disable QUIC path MTU discovery")
	cmd.Flags().StringVar(&v.HTTP2IdleTimeout, "hy2-http2-idle-timeout", "", "HTTP2 idle timeout")
	cmd.Flags().StringVar(&v.HTTP2KeepAlivePeriod, "hy2-http2-keep-alive-period", "", "HTTP2 keep alive period")
	cmd.Flags().StringVar(&v.HTTP2StreamReceiveWindow, "hy2-http2-stream-receive-window", "", "HTTP2 stream receive window")
	cmd.Flags().StringVar(&v.HTTP2ConnectionReceiveWindow, "hy2-http2-connection-receive-window", "", "HTTP2 connection receive window")
	cmd.Flags().IntVar(&v.HTTP2MaxConcurrentStreams, "hy2-http2-max-concurrent-streams", 0, "HTTP2 max concurrent streams")

	cmd.Flags().StringVar(&v.RealmServerURL, "hy2-realm-server-url", "", "Hysteria Realm rendezvous service URL")
	cmd.Flags().StringVar(&v.RealmToken, "hy2-realm-token", "", "Hysteria Realm bearer token")
	cmd.Flags().StringVar(&v.RealmID, "hy2-realm-id", "", "Hysteria Realm slot identifier")
	cmd.Flags().StringSliceVar(&v.RealmSTUNServers, "hy2-realm-stun-servers", nil, "STUN servers for Realm NAT traversal")
	cmd.Flags().StringVar(&v.RealmSTUNDomainResolver, "hy2-realm-stun-domain-resolver", "", "Domain resolver for STUN servers (JSON or server name)")
	cmd.Flags().StringVar(&v.RealmHTTPClientJSON, "hy2-realm-http-client", "", "HTTP client options for Realm (JSON object)")
}

// readHysteria2Input performs an internal helper operation.
func readHysteria2Input(v hysteria2FlagValues) orchestration.Hysteria2CreateOptions {
	return v.Hysteria2CreateOptions
}
