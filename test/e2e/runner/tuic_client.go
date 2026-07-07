package runner

import (
	"encoding/json"
	"fmt"

	"github.com/ivan-khludov/obscura/internal/protocol/tuic"
)

// TUICConnectConfig describes sing-box client settings for a TUIC E2E case.
type TUICConnectConfig struct {
	ServerHost string
	Port       int
	UUID       string
	Password   string
	Data       tuic.ProtocolData
}

// TUICConnectConfigFromCreate builds client connect settings from a create result.
func TUICConnectConfigFromCreate(result VPNCreateResult) (TUICConnectConfig, error) {
	data, err := tuic.ParseProtocolData(result.VPN.ProtocolData)
	if err != nil {
		return TUICConnectConfig{}, err
	}
	cfg := TUICConnectConfig{
		ServerHost: ServerHost,
		Port:       result.VPN.Listen.ListenPort,
		UUID:       result.Client.Username,
		Password:   result.Client.Password,
		Data:       data,
	}
	if cfg.UUID == "" {
		return TUICConnectConfig{}, fmt.Errorf("empty client uuid")
	}
	if cfg.Password == "" {
		return TUICConnectConfig{}, fmt.Errorf("empty client password")
	}
	if data.CertPath == "" && (data.ACME == nil || len(data.ACME.Domains) == 0) {
		return TUICConnectConfig{}, fmt.Errorf("missing tls credentials in protocol data")
	}
	return cfg, nil
}

// BuildTUICClientConfig renders a sing-box client JSON for TUIC E2E.
func BuildTUICClientConfig(cfg TUICConnectConfig) ([]byte, error) {
	inbound := map[string]any{
		"type":        "mixed",
		"tag":         "mixed-in",
		"listen":      "127.0.0.1",
		"listen_port": localMixedPort,
	}
	cc := cfg.Data.CongestionControl
	if cc == "" {
		cc = tuic.CongestionCubic
	}
	outbound := map[string]any{
		"type":               "tuic",
		"tag":                "proxy",
		"server":             cfg.ServerHost,
		"server_port":        cfg.Port,
		"uuid":               cfg.UUID,
		"password":           cfg.Password,
		"congestion_control": cc,
		"udp_relay_mode":     "native",
		"tls":                buildTUICClientTLS(cfg.Data),
	}
	if cfg.Data.ZeroRTTHandshake {
		outbound["zero_rtt_handshake"] = true
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

func buildTUICClientTLS(data tuic.ProtocolData) map[string]any {
	tls := map[string]any{"enabled": true, "insecure": true}
	if data.ServerName != "" {
		tls["server_name"] = data.ServerName
	}
	alpn := data.ALPN
	if len(alpn) == 0 {
		alpn = append([]string{}, tuic.DefaultALPN...)
	}
	tls["alpn"] = alpn
	return tls
}

// CheckTUICClientConfig validates a TUIC client sing-box config on the client container.
func (r *Runner) CheckTUICClientConfig(cfg TUICConnectConfig) error {
	r.t.Helper()
	raw, err := BuildTUICClientConfig(cfg)
	if err != nil {
		return err
	}
	return r.checkSingBoxConfig(raw)
}

// CurlViaTUIC runs sing-box on the client and fetches TargetURL through TUIC.
func (r *Runner) CurlViaTUIC(cfg TUICConnectConfig) error {
	r.t.Helper()
	raw, err := BuildTUICClientConfig(cfg)
	if err != nil {
		return err
	}
	return r.curlViaSingBoxConfig(raw)
}
