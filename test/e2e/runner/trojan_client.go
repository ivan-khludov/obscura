package runner

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/protocol/trojan"
)

// TrojanConnectConfig describes sing-box client settings for a Trojan E2E case.
type TrojanConnectConfig struct {
	ServerHost       string
	Port             int
	Password         string
	Data             trojan.ProtocolData
	Multiplex        bool
	MultiplexPadding bool
}

// TrojanConnectConfigFromCreate builds client connect settings from a create result.
func TrojanConnectConfigFromCreate(result VPNCreateResult, multiplex, multiplexPadding bool) (TrojanConnectConfig, error) {
	data, err := trojan.ParseProtocolData(result.VPN.ProtocolData)
	if err != nil {
		return TrojanConnectConfig{}, err
	}
	cfg := TrojanConnectConfig{
		ServerHost:       ServerHost,
		Port:             result.VPN.Listen.ListenPort,
		Password:         result.Client.Password,
		Data:             data,
		Multiplex:        multiplex,
		MultiplexPadding: multiplexPadding,
	}
	if cfg.Password == "" {
		return TrojanConnectConfig{}, fmt.Errorf("empty client password")
	}
	if cfg.Data.RealityEnabled {
		if cfg.Data.RealityPrivateKey == "" {
			return TrojanConnectConfig{}, fmt.Errorf("empty reality private key in protocol data")
		}
		if len(cfg.Data.RealityShortIDs) == 0 {
			return TrojanConnectConfig{}, fmt.Errorf("empty reality short_id in protocol data")
		}
		if cfg.Data.RealityHandshakeServer == "" {
			return TrojanConnectConfig{}, fmt.Errorf("empty reality handshake server in protocol data")
		}
	} else if cfg.Data.CertPath == "" && (cfg.Data.ACME == nil || len(cfg.Data.ACME.Domains) == 0) {
		return TrojanConnectConfig{}, fmt.Errorf("missing tls credentials in protocol data")
	}
	return cfg, nil
}

// BuildTrojanClientConfig renders a sing-box client JSON for Trojan E2E.
func BuildTrojanClientConfig(cfg TrojanConnectConfig) ([]byte, error) {
	inbound := map[string]any{
		"type":        "mixed",
		"tag":         "mixed-in",
		"listen":      "127.0.0.1",
		"listen_port": localMixedPort,
	}
	outbound := map[string]any{
		"type":        "trojan",
		"tag":         "proxy",
		"server":      cfg.ServerHost,
		"server_port": cfg.Port,
		"password":    cfg.Password,
	}
	tls, err := buildTrojanClientTLS(cfg.Data)
	if err != nil {
		return nil, err
	}
	outbound["tls"] = tls
	if cfg.Multiplex {
		outbound["multiplex"] = multiplexOptions(cfg.MultiplexPadding)
	}
	if transport := buildTrojanClientTransport(cfg.Data); transport != nil {
		outbound["transport"] = transport
	}
	config := map[string]any{
		"inbounds": []map[string]any{inbound},
		"outbounds": []map[string]any{
			{"type": "direct", "tag": "direct"},
			{"type": "block", "tag": "block"},
			outbound,
		},
		"route": map[string]any{"final": "proxy"},
	}
	return json.Marshal(config)
}

func buildTrojanClientTLS(data trojan.ProtocolData) (map[string]any, error) {
	tls := map[string]any{"enabled": true}
	if data.RealityEnabled {
		publicKey := data.RealityPublicKey
		if publicKey == "" {
			var err error
			publicKey, err = trojan.RealityPublicKeyFromPrivate(data.RealityPrivateKey)
			if err != nil {
				return nil, fmt.Errorf("reality public key: %w", err)
			}
		}
		serverName := data.RealityHandshakeServer
		if serverName == "" {
			serverName = data.ServerName
		}
		tls["server_name"] = serverName
		tls["utls"] = map[string]any{
			"enabled":     true,
			"fingerprint": protocol.ResolveRealityUTLSFingerprint(data.RealityUTLSFingerprint),
		}
		tls["reality"] = map[string]any{
			"enabled":    true,
			"public_key": publicKey,
			"short_id":   data.RealityShortIDs[0],
		}
		return tls, nil
	}
	if data.ServerName != "" {
		tls["server_name"] = data.ServerName
	}
	if alpn := alpnForTransport(data.TransportType, data.ALPN); len(alpn) > 0 {
		tls["alpn"] = alpn
	}
	tls["insecure"] = true
	return tls, nil
}

func buildTrojanClientTransport(data trojan.ProtocolData) map[string]any {
	switch data.TransportType {
	case "", "tcp":
		return nil
	case "quic":
		return map[string]any{"type": "quic"}
	case "http":
		if data.TransportHTTP == nil {
			return nil
		}
		out := map[string]any{"type": "http"}
		if len(data.TransportHTTP.Host) > 0 {
			out["host"] = data.TransportHTTP.Host
		}
		if data.TransportHTTP.Path != "" {
			out["path"] = data.TransportHTTP.Path
		}
		if data.TransportHTTP.Method != "" {
			out["method"] = data.TransportHTTP.Method
		}
		if len(data.TransportHTTP.Headers) > 0 {
			out["headers"] = data.TransportHTTP.Headers
		}
		return out
	case "ws":
		if data.TransportWS == nil {
			return nil
		}
		out := map[string]any{"type": "ws"}
		if data.TransportWS.Path != "" {
			out["path"] = data.TransportWS.Path
		}
		if len(data.TransportWS.Headers) > 0 {
			out["headers"] = data.TransportWS.Headers
		}
		return out
	case "grpc":
		if data.TransportGRPC == nil {
			return nil
		}
		out := map[string]any{"type": "grpc"}
		if data.TransportGRPC.ServiceName != "" {
			out["service_name"] = data.TransportGRPC.ServiceName
		}
		if data.TransportGRPC.PermitWithoutStream {
			out["permit_without_stream"] = true
		}
		return out
	case "httpupgrade":
		if data.TransportHTTPUpgrade == nil {
			return nil
		}
		out := map[string]any{"type": "httpupgrade"}
		if data.TransportHTTPUpgrade.Host != "" {
			out["host"] = data.TransportHTTPUpgrade.Host
		}
		if data.TransportHTTPUpgrade.Path != "" {
			out["path"] = data.TransportHTTPUpgrade.Path
		}
		if len(data.TransportHTTPUpgrade.Headers) > 0 {
			out["headers"] = data.TransportHTTPUpgrade.Headers
		}
		return out
	default:
		return nil
	}
}

// CurlViaTrojan runs sing-box on the client and fetches TargetURL through Trojan.
func (r *Runner) CurlViaTrojan(cfg TrojanConnectConfig) error {
	r.t.Helper()
	raw, err := BuildTrojanClientConfig(cfg)
	if err != nil {
		return err
	}
	return r.curlViaSingBoxConfig(raw)
}

// curlViaSingBoxConfig runs sing-box on the client and fetches TargetURL through the config.
func (r *Runner) curlViaSingBoxConfig(raw []byte) error {
	r.t.Helper()
	b64 := base64.StdEncoding.EncodeToString(raw)
	script := fmt.Sprintf(`set -euo pipefail
if command -v pkill >/dev/null 2>&1; then pkill -f 'sing-box run -c /tmp/sb-e2e.json' 2>/dev/null || true; fi
sleep 0.5
echo %q | base64 -d >/tmp/sb-e2e.json
sing-box check -c /tmp/sb-e2e.json
sing-box run -c /tmp/sb-e2e.json & pid=$!
trap 'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true' EXIT
sleep 2
curl -sf --max-time 15 --proxy socks5h://127.0.0.1:%d %q`, b64, localMixedPort, TargetURL)
	_, err := r.clientExec("bash", "-c", script)
	return err
}
