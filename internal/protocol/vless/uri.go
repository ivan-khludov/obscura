package vless

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/protocol/listen"
)

// buildShareLink assembles protocol or input data from create parameters.
func buildShareLink(vpn domain.VPNConfig, data ProtocolData, client domain.ClientConfig, serverHost string) (string, error) {
	host := listen.ProxyHost(vpn, serverHost)
	flow, err := clientFlow(data, client)
	if err != nil {
		return "", fmt.Errorf("client flow: %w", err)
	}
	security := "none"
	sni := data.ServerName
	if data.RealityEnabled {
		security = "reality"
	} else if data.CertPath != "" || data.KeyPath != "" || (data.ACME != nil && len(data.ACME.Domains) > 0) {
		security = "tls"
	}
	if sni == "" {
		sni = host
	}
	netType := shareNetType(data)
	path := ""
	hostHeader := ""
	if data.TransportWS != nil {
		path = data.TransportWS.Path
	}
	if data.TransportHTTP != nil {
		if len(data.TransportHTTP.Host) > 0 {
			hostHeader = data.TransportHTTP.Host[0]
		}
		path = data.TransportHTTP.Path
	}
	if data.TransportHTTPUpgrade != nil {
		hostHeader = data.TransportHTTPUpgrade.Host
		path = data.TransportHTTPUpgrade.Path
	}
	if data.TransportGRPC != nil && data.TransportGRPC.ServiceName != "" {
		path = data.TransportGRPC.ServiceName
	}
	remark := client.Name
	if remark == "" {
		remark = "vless"
	}
	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("security", security)
	q.Set("type", netType)
	if sni != "" {
		q.Set("sni", sni)
	}
	if path != "" {
		q.Set("path", path)
	}
	if hostHeader != "" {
		q.Set("host", hostHeader)
	}
	if flow != "" {
		q.Set("flow", flow)
	}
	if security == "tls" && protocol.ShareLinkInsecureTLS(TLSMode(data)) {
		q.Set("allowInsecure", "1")
	}
	if data.RealityEnabled && data.RealityPublicKey != "" {
		q.Set("fp", protocol.ResolveRealityUTLSFingerprint(data.RealityUTLSFingerprint))
		q.Set("pbk", data.RealityPublicKey)
		if len(data.RealityShortIDs) > 0 {
			q.Set("sid", data.RealityShortIDs[0])
		}
	}
	if len(data.ALPN) > 0 {
		q.Set("alpn", strings.Join(data.ALPN, ","))
	}
	userInfo := url.User(client.Password)
	return fmt.Sprintf("vless://%s@%s:%d?%s#%s",
		userInfo.String(),
		host,
		vpn.Listen.ListenPort,
		q.Encode(),
		url.PathEscape(remark),
	), nil
}

// shareNetType performs an internal helper operation.
func shareNetType(data ProtocolData) string {
	switch data.TransportType {
	case "ws":
		return "ws"
	case "grpc":
		return "grpc"
	case "http":
		return "http"
	case "httpupgrade":
		return "httpupgrade"
	case "quic":
		return "quic"
	default:
		return "tcp"
	}
}
