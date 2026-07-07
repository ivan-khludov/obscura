package runner

import (
	"encoding/json"
	"fmt"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/protocol/trojan"
	"github.com/ivan-khludov/obscura/internal/protocol/vless"
)

// VLESSConnectConfig describes sing-box client settings for a VLESS E2E case.
type VLESSConnectConfig struct {
	ServerHost              string
	Port                    int
	UUID                    string
	Flow                    string
	Data                    vless.ProtocolData
	Multiplex               bool
	MultiplexPadding        bool
	MultiplexBrutal         bool
	MultiplexBrutalUpMbps   int
	MultiplexBrutalDownMbps int
}

// VLESSConnectConfigFromCreate builds client connect settings from a create result.
func VLESSConnectConfigFromCreate(result VPNCreateResult, multiplex, multiplexPadding, multiplexBrutal bool, brutalUp, brutalDown int) (VLESSConnectConfig, error) {
	data, err := vless.ParseProtocolData(result.VPN.ProtocolData)
	if err != nil {
		return VLESSConnectConfig{}, err
	}
	flow, err := vlessClientFlow(data, result.Client)
	if err != nil {
		return VLESSConnectConfig{}, err
	}
	cfg := VLESSConnectConfig{
		ServerHost:              ServerHost,
		Port:                    result.VPN.Listen.ListenPort,
		UUID:                    result.Client.Password,
		Flow:                    flow,
		Data:                    data,
		Multiplex:               multiplex,
		MultiplexPadding:        multiplexPadding,
		MultiplexBrutal:         multiplexBrutal,
		MultiplexBrutalUpMbps:   brutalUp,
		MultiplexBrutalDownMbps: brutalDown,
	}
	if cfg.UUID == "" {
		return VLESSConnectConfig{}, fmt.Errorf("empty client uuid")
	}
	if data.RealityEnabled {
		if data.RealityPrivateKey == "" {
			return VLESSConnectConfig{}, fmt.Errorf("empty reality private key in protocol data")
		}
		if len(data.RealityShortIDs) == 0 {
			return VLESSConnectConfig{}, fmt.Errorf("empty reality short_id in protocol data")
		}
		if data.RealityHandshakeServer == "" {
			return VLESSConnectConfig{}, fmt.Errorf("empty reality handshake server in protocol data")
		}
		return cfg, nil
	}
	if data.CertPath == "" && (data.ACME == nil || len(data.ACME.Domains) == 0) {
		return VLESSConnectConfig{}, fmt.Errorf("missing tls credentials in protocol data")
	}
	return cfg, nil
}

func vlessClientFlow(data vless.ProtocolData, client domain.Client) (string, error) {
	flow := data.DefaultFlow
	if client.Username != "" {
		flow = client.Username
	}
	if err := vless.ValidateClientFlow(flow); err != nil {
		return "", err
	}
	if flow == vless.FlowVision && data.TransportType != "" {
		return "", fmt.Errorf("xtls-rprx-vision flow requires direct transport")
	}
	return flow, nil
}

// BuildVLESSClientConfig renders a sing-box client JSON for VLESS E2E.
func BuildVLESSClientConfig(cfg VLESSConnectConfig) ([]byte, error) {
	inbound := map[string]any{
		"type":        "mixed",
		"tag":         "mixed-in",
		"listen":      "127.0.0.1",
		"listen_port": localMixedPort,
	}
	outbound := map[string]any{
		"type":        "vless",
		"tag":         "proxy",
		"server":      cfg.ServerHost,
		"server_port": cfg.Port,
		"uuid":        cfg.UUID,
	}
	if cfg.Flow != "" {
		outbound["flow"] = cfg.Flow
	}
	tls, err := buildVLESSClientTLS(cfg.Data)
	if err != nil {
		return nil, err
	}
	outbound["tls"] = tls
	if cfg.Multiplex {
		outbound["multiplex"] = vlessMultiplexOptions(cfg)
	}
	if transport := buildVLESSClientTransport(cfg.Data); transport != nil {
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

func buildVLESSClientTLS(data vless.ProtocolData) (map[string]any, error) {
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

func vlessMultiplexOptions(cfg VLESSConnectConfig) map[string]any {
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

func buildVLESSClientTransport(data vless.ProtocolData) map[string]any {
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

// CheckVlessClientConfig validates a VLESS client sing-box config on the client container.
func (r *Runner) CheckVlessClientConfig(cfg VLESSConnectConfig) error {
	r.t.Helper()
	raw, err := BuildVLESSClientConfig(cfg)
	if err != nil {
		return err
	}
	return r.checkSingBoxConfig(raw)
}

// CurlViaVless runs sing-box on the client and fetches TargetURL through VLESS.
func (r *Runner) CurlViaVless(cfg VLESSConnectConfig) error {
	r.t.Helper()
	raw, err := BuildVLESSClientConfig(cfg)
	if err != nil {
		return err
	}
	return r.curlViaSingBoxConfig(raw)
}
