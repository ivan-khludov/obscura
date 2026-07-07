package runner

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/protocol/trojan"
	"github.com/ivan-khludov/obscura/internal/protocol/vmess"
)

// VMessConnectConfig describes sing-box client settings for a VMess E2E case.
type VMessConnectConfig struct {
	ServerHost              string
	Port                    int
	UUID                    string
	AlterID                 int
	Data                    vmess.ProtocolData
	Multiplex               bool
	MultiplexPadding        bool
	MultiplexBrutal         bool
	MultiplexBrutalUpMbps   int
	MultiplexBrutalDownMbps int
}

// VMessConnectConfigFromCreate builds client connect settings from a create result.
func VMessConnectConfigFromCreate(result VPNCreateResult, multiplex, multiplexPadding, multiplexBrutal bool, brutalUp, brutalDown int) (VMessConnectConfig, error) {
	data, err := vmess.ParseProtocolData(result.VPN.ProtocolData)
	if err != nil {
		return VMessConnectConfig{}, err
	}
	alterID, err := vmessClientAlterID(data, result.Client)
	if err != nil {
		return VMessConnectConfig{}, err
	}
	cfg := VMessConnectConfig{
		ServerHost:              ServerHost,
		Port:                    result.VPN.Listen.ListenPort,
		UUID:                    result.Client.Password,
		AlterID:                 alterID,
		Data:                    data,
		Multiplex:               multiplex,
		MultiplexPadding:        multiplexPadding,
		MultiplexBrutal:         multiplexBrutal,
		MultiplexBrutalUpMbps:   brutalUp,
		MultiplexBrutalDownMbps: brutalDown,
	}
	if cfg.UUID == "" {
		return VMessConnectConfig{}, fmt.Errorf("empty client uuid")
	}
	if data.TLSDisabled {
		return cfg, nil
	}
	if data.RealityEnabled {
		if data.RealityPrivateKey == "" {
			return VMessConnectConfig{}, fmt.Errorf("empty reality private key in protocol data")
		}
		if len(data.RealityShortIDs) == 0 {
			return VMessConnectConfig{}, fmt.Errorf("empty reality short_id in protocol data")
		}
		if data.RealityHandshakeServer == "" {
			return VMessConnectConfig{}, fmt.Errorf("empty reality handshake server in protocol data")
		}
		return cfg, nil
	}
	if data.CertPath == "" && (data.ACME == nil || len(data.ACME.Domains) == 0) {
		return VMessConnectConfig{}, fmt.Errorf("missing tls credentials in protocol data")
	}
	return cfg, nil
}

func vmessClientAlterID(data vmess.ProtocolData, client domain.Client) (int, error) {
	if client.Username != "" {
		alterID, err := strconv.Atoi(client.Username)
		if err != nil || alterID < 0 || alterID > 65535 {
			return 0, fmt.Errorf("alterId must be 0-65535")
		}
		return alterID, nil
	}
	return data.DefaultAlterId, nil
}

// BuildVMessClientConfig renders a sing-box client JSON for VMess E2E.
func BuildVMessClientConfig(cfg VMessConnectConfig) ([]byte, error) {
	inbound := map[string]any{
		"type":        "mixed",
		"tag":         "mixed-in",
		"listen":      "127.0.0.1",
		"listen_port": localMixedPort,
	}
	outbound := map[string]any{
		"type":        "vmess",
		"tag":         "proxy",
		"server":      cfg.ServerHost,
		"server_port": cfg.Port,
		"uuid":        cfg.UUID,
		"alter_id":    cfg.AlterID,
		"security":    "auto",
	}
	if !cfg.Data.TLSDisabled {
		tls, err := buildVMessClientTLS(cfg.Data)
		if err != nil {
			return nil, err
		}
		outbound["tls"] = tls
	}
	if cfg.Multiplex {
		outbound["multiplex"] = vmessMultiplexOptions(cfg)
	}
	if transport := buildVMessClientTransport(cfg.Data); transport != nil {
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

func buildVMessClientTLS(data vmess.ProtocolData) (map[string]any, error) {
	tls := map[string]any{"enabled": true}
	if data.RealityEnabled {
		publicKey, err := trojan.RealityPublicKeyFromPrivate(data.RealityPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("reality public key: %w", err)
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

func vmessMultiplexOptions(cfg VMessConnectConfig) map[string]any {
	m := multiplexOptions(cfg.MultiplexPadding)
	if cfg.MultiplexBrutal {
		m["brutal"] = map[string]any{
			"enabled":   true,
			"up_mbps":   cfg.MultiplexBrutalUpMbps,
			"down_mbps": cfg.MultiplexBrutalDownMbps,
		}
	}
	return m
}

func buildVMessClientTransport(data vmess.ProtocolData) map[string]any {
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

// CheckVMessClientConfig validates a VMess client sing-box config on the client container.
func (r *Runner) CheckVMessClientConfig(cfg VMessConnectConfig) error {
	r.t.Helper()
	raw, err := BuildVMessClientConfig(cfg)
	if err != nil {
		return err
	}
	return r.checkSingBoxConfig(raw)
}

func (r *Runner) checkSingBoxConfig(raw []byte) error {
	r.t.Helper()
	b64 := base64.StdEncoding.EncodeToString(raw)
	script := fmt.Sprintf(`set -euo pipefail
echo %q | base64 -d >/tmp/sb-e2e-check.json
sing-box check -c /tmp/sb-e2e-check.json`, b64)
	_, err := r.clientExec("bash", "-c", script)
	return err
}

// CurlViaVmess runs sing-box on the client and fetches TargetURL through VMess.
func (r *Runner) CurlViaVmess(cfg VMessConnectConfig) error {
	r.t.Helper()
	raw, err := BuildVMessClientConfig(cfg)
	if err != nil {
		return err
	}
	return r.curlViaSingBoxConfig(raw)
}
