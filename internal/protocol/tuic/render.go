package tuic

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
	})
}

// applyQUICFields applies transport, TLS preview, or option fields to protocol data.
func applyQUICFields(target map[string]any, data ProtocolData) {
	inbound.ApplyQUICFields(target, data.HTTP2, data.InitialPacketSize, data.DisablePathMTUDiscovery)
}

// UsersFromClients builds sing-box TUIC user entries from enabled clients.
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
			"uuid":     c.Username,
			"password": c.Password,
		})
	}
	return users
}
