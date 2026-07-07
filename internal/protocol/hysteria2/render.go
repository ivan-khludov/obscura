package hysteria2

import (
	"encoding/json"

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

// renderObfs renders sing-box configuration fragments for the protocol.
func renderObfs(data ProtocolData) map[string]any {
	if data.ObfsPassword == "" {
		return nil
	}
	return map[string]any{
		"type":     "salamander",
		"password": data.ObfsPassword,
	}
}

// renderMasquerade renders sing-box configuration fragments for the protocol.
func renderMasquerade(data ProtocolData) any {
	if data.MasqueradeURL != "" {
		return data.MasqueradeURL
	}
	if data.Masquerade == nil {
		return nil
	}
	m := data.Masquerade
	out := map[string]any{"type": m.Type}
	switch m.Type {
	case MasqueradeTypeFile:
		out["directory"] = m.Directory
	case MasqueradeTypeProxy:
		out["url"] = m.URL
		if m.RewriteHost {
			out["rewrite_host"] = true
		}
	case MasqueradeTypeString:
		out["status_code"] = m.StatusCode
		if len(m.Headers) > 0 {
			out["headers"] = m.Headers
		}
		if m.Content != "" {
			out["content"] = m.Content
		}
	}
	return out
}

// renderRealm renders sing-box configuration fragments for the protocol.
func renderRealm(r *RealmOptions) map[string]any {
	if r == nil {
		return nil
	}
	out := map[string]any{
		"server_url":   r.ServerURL,
		"realm_id":     r.RealmID,
		"stun_servers": r.STUNServers,
	}
	if r.Token != "" {
		out["token"] = r.Token
	}
	if len(r.STUNDomainResolver) > 0 {
		var resolver any
		if err := json.Unmarshal(r.STUNDomainResolver, &resolver); err == nil {
			out["stun_domain_resolver"] = resolver
		}
	}
	if len(r.HTTPClient) > 0 {
		var client any
		if err := json.Unmarshal(r.HTTPClient, &client); err == nil {
			out["http_client"] = client
		}
	}
	return out
}

// applyQUICFields applies transport, TLS preview, or option fields to protocol data.
func applyQUICFields(target map[string]any, data ProtocolData) {
	inbound.ApplyQUICFields(target, data.HTTP2, data.InitialPacketSize, data.DisablePathMTUDiscovery)
}

// UsersFromClients builds sing-box Hysteria2 user entries from enabled clients.
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
