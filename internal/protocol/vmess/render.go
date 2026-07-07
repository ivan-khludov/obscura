package vmess

import (
	"fmt"
	"strconv"

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
	return inbound.RenderMultiplex(data.MultiplexPadding, data.MultiplexBrutal, data.MultiplexBrutalUpMbps, data.MultiplexBrutalDownMbps)
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

// UsersFromClients builds sing-box VMess user entries from enabled clients.
func UsersFromClients(data ProtocolData, clients []domain.ClientConfig) ([]map[string]any, error) {
	if usersFromClientsHook != nil {
		return usersFromClientsHook(data, clients)
	}
	return usersFromClientsImpl(data, clients)
}

var usersFromClientsHook func(ProtocolData, []domain.ClientConfig) ([]map[string]any, error)

func usersFromClientsImpl(data ProtocolData, clients []domain.ClientConfig) ([]map[string]any, error) {
	users := make([]map[string]any, 0)
	for _, c := range clients {
		if !c.Enabled {
			continue
		}
		name := c.Name
		if name == "" {
			name = c.Username
		}
		alterID, err := clientAlterID(data, c)
		if err != nil {
			return nil, err
		}
		users = append(users, map[string]any{
			"name":    name,
			"uuid":    c.Password,
			"alterId": alterID,
		})
	}
	return users, nil
}

// clientAlterID performs an internal helper operation.
func clientAlterID(data ProtocolData, client domain.ClientConfig) (int, error) {
	if client.Username != "" {
		alterID, err := strconv.Atoi(client.Username)
		if err != nil || alterID < 0 || alterID > 65535 {
			return 0, fmt.Errorf("alterId must be 0-65535")
		}
		return alterID, nil
	}
	return data.DefaultAlterId, nil
}
