package orchestration

import (
	"strings"

	"github.com/ivan-khludov/obscura/internal/protocol/hysteria2"
	"github.com/ivan-khludov/obscura/internal/protocol/vless"
	"github.com/ivan-khludov/obscura/internal/protocol/wireguard"
)

// BuildTrojanCreateOptions composes trojan options from shared toggles.
func BuildTrojanCreateOptions(base TrojanCreateOptions, multiplex, multiplexPadding, fallbackStub bool) TrojanCreateOptions {
	out := base
	out.Multiplex = multiplex
	out.MultiplexPadding = multiplexPadding
	if fallbackStub {
		if out.FallbackServer == "" {
			out.FallbackServer = "127.0.0.1"
		}
		if out.FallbackPort == 0 {
			out.FallbackPort = 8080
		}
	}
	return out
}

// BuildTrojanCreateOptionsFromFields composes trojan options from primitive adapter fields.
func BuildTrojanCreateOptionsFromFields(
	serverName, transport, transportPath, transportHost, transportServiceName string,
	multiplex, multiplexPadding bool,
	fallbackPort int,
) TrojanCreateOptions {
	in := BuildTrojanCreateOptions(TrojanCreateOptions{
		ServerName:           serverName,
		Transport:            transport,
		TransportPath:        transportPath,
		TransportHost:        transportHost,
		TransportServiceName: transportServiceName,
	}, multiplex, multiplexPadding, false)
	if fallbackPort > 0 {
		in.FallbackServer = "127.0.0.1"
		in.FallbackPort = fallbackPort
	}
	return in
}

// BuildVMessCreateOptions composes vmess options from shared TLS/transport fields.
func BuildVMessCreateOptions(base VMessCreateOptions, trojanIn TrojanCreateOptions, multiplexBrutal bool, brutalUp, brutalDown int) VMessCreateOptions {
	out := base
	out.ServerName = trojanIn.ServerName
	out.ALPN = trojanIn.ALPN
	out.CertPath = trojanIn.CertPath
	out.KeyPath = trojanIn.KeyPath
	out.MinVersion = trojanIn.MinVersion
	out.MaxVersion = trojanIn.MaxVersion
	out.CipherSuites = trojanIn.CipherSuites
	out.CurvePreferences = trojanIn.CurvePreferences
	out.ClientAuthentication = trojanIn.ClientAuthentication
	out.ClientCertificatePaths = trojanIn.ClientCertificatePaths
	out.ClientCertificatePublicKeySHA256 = trojanIn.ClientCertificatePublicKeySHA256
	out.KernelTX = trojanIn.KernelTX
	out.KernelRX = trojanIn.KernelRX
	out.HandshakeTimeout = trojanIn.HandshakeTimeout
	out.ACMEDomains = trojanIn.ACMEDomains
	out.ACMEEmail = trojanIn.ACMEEmail
	out.ACMEProvider = trojanIn.ACMEProvider
	out.ACMEDataDirectory = trojanIn.ACMEDataDirectory
	out.ACMEDefaultServerName = trojanIn.ACMEDefaultServerName
	out.ACMEDisableHTTPChallenge = trojanIn.ACMEDisableHTTPChallenge
	out.ACMEDisableTLSALPNChallenge = trojanIn.ACMEDisableTLSALPNChallenge
	out.ACMEAlternativeHTTPPort = trojanIn.ACMEAlternativeHTTPPort
	out.ACMEAlternativeTLSPort = trojanIn.ACMEAlternativeTLSPort
	out.Reality = trojanIn.Reality
	out.RealityHandshake = trojanIn.RealityHandshake
	out.RealityHandshakePort = trojanIn.RealityHandshakePort
	out.RealityPrivateKey = trojanIn.RealityPrivateKey
	out.RealityShortIDs = trojanIn.RealityShortIDs
	out.RealityMaxTimeDifference = trojanIn.RealityMaxTimeDifference
	out.RealityUTLSFingerprint = trojanIn.RealityUTLSFingerprint
	out.ECH = trojanIn.ECH
	out.ECHKeyPath = trojanIn.ECHKeyPath
	out.FallbackServer = trojanIn.FallbackServer
	out.FallbackPort = trojanIn.FallbackPort
	out.FallbackForALPNJSON = trojanIn.FallbackForALPNJSON
	out.Multiplex = trojanIn.Multiplex
	out.MultiplexPadding = trojanIn.MultiplexPadding
	out.MultiplexBrutal = multiplexBrutal
	out.MultiplexBrutalUpMbps = brutalUp
	out.MultiplexBrutalDownMbps = brutalDown
	out.Transport = trojanIn.Transport
	out.TransportPath = trojanIn.TransportPath
	out.TransportHost = trojanIn.TransportHost
	out.TransportHosts = trojanIn.TransportHosts
	out.TransportServiceName = trojanIn.TransportServiceName
	out.TransportMethod = trojanIn.TransportMethod
	out.TransportHeadersJSON = trojanIn.TransportHeadersJSON
	out.WSMaxEarlyData = trojanIn.WSMaxEarlyData
	out.WSEarlyDataHeaderName = trojanIn.WSEarlyDataHeaderName
	out.GRPCPermitWithoutStream = trojanIn.GRPCPermitWithoutStream
	return out
}

// BuildVMessCreateOptionsFromFields composes VMess options from primitive adapter fields.
func BuildVMessCreateOptionsFromFields(noTLS bool, trojanIn TrojanCreateOptions) VMessCreateOptions {
	return BuildVMessCreateOptions(VMessCreateOptions{NoTLS: noTLS}, trojanIn, false, 0, 0)
}

// BuildVLESSCreateOptions composes vless options from shared TLS/transport fields.
func BuildVLESSCreateOptions(base VLESSCreateOptions, trojanIn TrojanCreateOptions, multiplexBrutal bool, brutalUp, brutalDown int) VLESSCreateOptions {
	out := base
	if out.DefaultFlow == "xtls-rprx-vision" || out.DefaultFlow == vless.FlowVision {
		out.DefaultFlow = vless.FlowVision
	}
	out.ServerName = trojanIn.ServerName
	out.ALPN = trojanIn.ALPN
	out.CertPath = trojanIn.CertPath
	out.KeyPath = trojanIn.KeyPath
	out.MinVersion = trojanIn.MinVersion
	out.MaxVersion = trojanIn.MaxVersion
	out.CipherSuites = trojanIn.CipherSuites
	out.CurvePreferences = trojanIn.CurvePreferences
	out.ClientAuthentication = trojanIn.ClientAuthentication
	out.ClientCertificatePaths = trojanIn.ClientCertificatePaths
	out.ClientCertificatePublicKeySHA256 = trojanIn.ClientCertificatePublicKeySHA256
	out.KernelTX = trojanIn.KernelTX
	out.KernelRX = trojanIn.KernelRX
	out.HandshakeTimeout = trojanIn.HandshakeTimeout
	out.ACMEDomains = trojanIn.ACMEDomains
	out.ACMEEmail = trojanIn.ACMEEmail
	out.ACMEProvider = trojanIn.ACMEProvider
	out.ACMEDataDirectory = trojanIn.ACMEDataDirectory
	out.ACMEDefaultServerName = trojanIn.ACMEDefaultServerName
	out.ACMEDisableHTTPChallenge = trojanIn.ACMEDisableHTTPChallenge
	out.ACMEDisableTLSALPNChallenge = trojanIn.ACMEDisableTLSALPNChallenge
	out.ACMEAlternativeHTTPPort = trojanIn.ACMEAlternativeHTTPPort
	out.ACMEAlternativeTLSPort = trojanIn.ACMEAlternativeTLSPort
	out.Reality = trojanIn.Reality
	out.RealityHandshake = trojanIn.RealityHandshake
	out.RealityHandshakePort = trojanIn.RealityHandshakePort
	out.RealityPrivateKey = trojanIn.RealityPrivateKey
	out.RealityShortIDs = trojanIn.RealityShortIDs
	out.RealityMaxTimeDifference = trojanIn.RealityMaxTimeDifference
	out.RealityUTLSFingerprint = trojanIn.RealityUTLSFingerprint
	out.ECH = trojanIn.ECH
	out.ECHKeyPath = trojanIn.ECHKeyPath
	out.FallbackServer = trojanIn.FallbackServer
	out.FallbackPort = trojanIn.FallbackPort
	out.FallbackForALPNJSON = trojanIn.FallbackForALPNJSON
	out.Multiplex = trojanIn.Multiplex
	out.MultiplexPadding = trojanIn.MultiplexPadding
	out.MultiplexBrutal = multiplexBrutal
	out.MultiplexBrutalUpMbps = brutalUp
	out.MultiplexBrutalDownMbps = brutalDown
	out.Transport = trojanIn.Transport
	out.TransportPath = trojanIn.TransportPath
	out.TransportHost = trojanIn.TransportHost
	out.TransportHosts = trojanIn.TransportHosts
	out.TransportServiceName = trojanIn.TransportServiceName
	out.TransportMethod = trojanIn.TransportMethod
	out.TransportHeadersJSON = trojanIn.TransportHeadersJSON
	out.WSMaxEarlyData = trojanIn.WSMaxEarlyData
	out.WSEarlyDataHeaderName = trojanIn.WSEarlyDataHeaderName
	out.GRPCPermitWithoutStream = trojanIn.GRPCPermitWithoutStream
	return out
}

// BuildVLESSCreateOptionsFromFields composes VLESS options from primitive adapter fields.
func BuildVLESSCreateOptionsFromFields(defaultFlow string, reality bool, realityUTLSFingerprint string, trojanIn TrojanCreateOptions) VLESSCreateOptions {
	return BuildVLESSCreateOptions(VLESSCreateOptions{
		DefaultFlow:            defaultFlow,
		Reality:                reality,
		RealityHandshake:       trojanIn.ServerName,
		RealityUTLSFingerprint: realityUTLSFingerprint,
	}, trojanIn, false, 0, 0)
}

// BuildShadowsocksCreateOptions composes shadowsocks options from shared inputs.
func BuildShadowsocksCreateOptions(
	method, plugin, pluginOpts string,
	multiplex, multiplexPadding, shadowTLS bool,
	shadowTLSHandshake string, shadowTLSHandshakePort int, shadowTLSStrictMode bool,
	listenPort int,
) ShadowsocksCreateOptions {
	return ShadowsocksCreateOptions{
		Method:                 method,
		Plugin:                 plugin,
		PluginOpts:             pluginOpts,
		Multiplex:              multiplex,
		MultiplexPadding:       multiplexPadding,
		ShadowTLS:              shadowTLS,
		ShadowTLSHandshake:     shadowTLSHandshake,
		ShadowTLSHandshakePort: shadowTLSHandshakePort,
		ShadowTLSStrictMode:    shadowTLSStrictMode,
		ListenPort:             listenPort,
	}
}

// BuildWireguardCreateOptions composes wireguard options from adapter values.
func BuildWireguardCreateOptions(system bool, address string, mtu int) WireguardCreateOptions {
	if strings.TrimSpace(address) == "" {
		address = wireguard.DefaultAddress
	}
	return WireguardCreateOptions{
		System:  system,
		Address: []string{address},
		MTU:     mtu,
	}
}

// BuildTUICCreateOptions composes TUIC options from adapter values.
func BuildTUICCreateOptions(serverName, congestionControl string, zeroRTT bool) TUICCreateOptions {
	return TUICCreateOptions{
		ServerName:        serverName,
		CongestionControl: congestionControl,
		ZeroRTTHandshake:  zeroRTT,
	}
}

// BuildHysteria2CreateOptions composes hysteria2 options from adapter values.
func BuildHysteria2CreateOptions(serverName string, upMbps, downMbps int, ignoreClientBandwidth bool, obfsPassword, masqueradeURL string) Hysteria2CreateOptions {
	in := Hysteria2CreateOptions{
		ServerName:            serverName,
		UpMbps:                upMbps,
		DownMbps:              downMbps,
		IgnoreClientBandwidth: ignoreClientBandwidth,
	}
	if obfsPassword != "" {
		in.ObfsPassword = obfsPassword
	}
	if masqueradeURL != "" {
		if strings.HasPrefix(masqueradeURL, "file://") {
			in.MasqueradeType = hysteria2.MasqueradeTypeFile
			in.MasqueradeDirectory = strings.TrimPrefix(masqueradeURL, "file://")
		} else if strings.HasPrefix(masqueradeURL, "http://") || strings.HasPrefix(masqueradeURL, "https://") {
			in.MasqueradeType = hysteria2.MasqueradeTypeProxy
			in.MasqueradeProxyURL = masqueradeURL
		} else {
			in.MasqueradeURL = masqueradeURL
		}
	}
	return in
}
