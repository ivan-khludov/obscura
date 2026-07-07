package trojan

import (
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/inbound"
)

// renderTLS renders sing-box configuration fragments for the protocol.
func renderTLS(data ProtocolData) map[string]any {
	return inbound.RenderTLSCore(inbound.TLSCoreParams{
		ServerName:                       data.ServerName,
		ALPN:                             data.ALPN,
		MinVersion:                       data.MinVersion,
		MaxVersion:                       data.MaxVersion,
		CipherSuites:                     data.CipherSuites,
		CurvePreferences:                 data.CurvePreferences,
		ClientAuthentication:             data.ClientAuthentication,
		ClientCertificatePaths:           data.ClientCertificatePaths,
		ClientCertificatePublicKeySHA256: data.ClientCertificatePublicKeySHA256,
		KernelTX:                         data.KernelTX,
		KernelRX:                         data.KernelRX,
		HandshakeTimeout:                 data.HandshakeTimeout,
		CertPath:                         data.CertPath,
		KeyPath:                          data.KeyPath,
		ACME:                             data.ACME,
		ECHEnabled:                       data.ECHEnabled,
		ECHKeyPath:                       data.ECHKeyPath,
		RealityEnabled:                   data.RealityEnabled,
		RealityHandshakeServer:           data.RealityHandshakeServer,
		Reality: &inbound.RealityParams{
			PrivateKey:        data.RealityPrivateKey,
			ShortIDs:          data.RealityShortIDs,
			HandshakeServer:   data.RealityHandshakeServer,
			HandshakePort:     realityHandshakePort(data),
			MaxTimeDifference: data.RealityMaxTimeDifference,
		},
	})
}

// renderMultiplex renders sing-box configuration fragments for the protocol.
func renderMultiplex(data ProtocolData) map[string]any {
	return inbound.RenderMultiplex(data.MultiplexPadding, false, 0, 0)
}

// renderFallback renders sing-box configuration fragments for the protocol.
func renderFallback(data ProtocolData) (map[string]any, map[string]any) {
	return inbound.RenderFallback(data.FallbackServer, data.FallbackPort, data.FallbackForALPN)
}

// renderTransport renders sing-box configuration fragments for the protocol.
func renderTransport(data ProtocolData) map[string]any {
	return inbound.RenderTransport(data.TransportType, data.TransportHTTP, data.TransportWS, data.TransportGRPC, data.TransportHTTPUpgrade)
}

// realityHandshakePort performs an internal helper operation.
func realityHandshakePort(data ProtocolData) int {
	if data.RealityHandshakePort == 0 {
		return DefaultRealityHandshakePort
	}
	return data.RealityHandshakePort
}

// UsersFromClients builds sing-box Trojan user entries from enabled clients.
func UsersFromClients(clients []domain.ClientConfig) []map[string]string {
	users := make([]map[string]string, 0)
	for _, c := range clients {
		if !c.Enabled {
			continue
		}
		name := c.Name
		if name == "" {
			name = c.Username
		}
		users = append(users, map[string]string{
			"name":     name,
			"password": c.Password,
		})
	}
	return users
}
