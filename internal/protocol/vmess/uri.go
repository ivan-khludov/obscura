package vmess

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/protocol/listen"
)

var jsonMarshal = json.Marshal

// buildShareLink assembles protocol or input data from create parameters.
func buildShareLink(vpn domain.VPNConfig, data ProtocolData, client domain.ClientConfig, serverHost string) (string, error) {
	host := listen.ProxyHost(vpn, serverHost)
	alterID, err := clientAlterID(data, client)
	if err != nil {
		return "", fmt.Errorf("client alterId: %w", err)
	}
	netType := shareNetType(data)
	tlsVal := ""
	if !data.TLSDisabled {
		tlsVal = "tls"
	}
	hostHeader := ""
	path := ""
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
	sni := data.ServerName
	if sni == "" {
		sni = host
	}
	remark := client.Name
	if remark == "" {
		remark = client.Username
	}
	payload := map[string]string{
		"v":    "2",
		"ps":   remark,
		"add":  host,
		"port": strconv.Itoa(vpn.Listen.ListenPort),
		"id":   client.Password,
		"aid":  strconv.Itoa(alterID),
		"scy":  "auto",
		"net":  netType,
		"type": "none",
		"host": hostHeader,
		"path": path,
		"tls":  tlsVal,
		"sni":  sni,
	}
	if len(data.ALPN) > 0 {
		payload["alpn"] = strings.Join(data.ALPN, ",")
	}
	if tlsVal == "tls" && protocol.ShareLinkInsecureTLS(TLSMode(data)) {
		payload["allowInsecure"] = "1"
	}
	raw, err := jsonMarshal(payload)
	if err != nil {
		return "", err
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(raw), nil
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
