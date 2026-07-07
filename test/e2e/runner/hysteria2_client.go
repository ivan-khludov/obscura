package runner

import (
	"encoding/json"
	"fmt"

	"github.com/ivan-khludov/obscura/internal/protocol/hysteria2"
)

// Hysteria2ConnectConfig describes sing-box client settings for a Hysteria2 E2E case.
type Hysteria2ConnectConfig struct {
	ServerHost string
	Port       int
	Password   string
	Data       hysteria2.ProtocolData
}

// Hysteria2ConnectConfigFromCreate builds client connect settings from a create result.
func Hysteria2ConnectConfigFromCreate(result VPNCreateResult) (Hysteria2ConnectConfig, error) {
	data, err := hysteria2.ParseProtocolData(result.VPN.ProtocolData)
	if err != nil {
		return Hysteria2ConnectConfig{}, err
	}
	cfg := Hysteria2ConnectConfig{
		ServerHost: ServerHost,
		Port:       result.VPN.Listen.ListenPort,
		Password:   result.Client.Password,
		Data:       data,
	}
	if cfg.Password == "" {
		return Hysteria2ConnectConfig{}, fmt.Errorf("empty client password")
	}
	if data.CertPath == "" && (data.ACME == nil || len(data.ACME.Domains) == 0) {
		return Hysteria2ConnectConfig{}, fmt.Errorf("missing tls credentials in protocol data")
	}
	return cfg, nil
}

// BuildHysteria2ClientConfig renders a sing-box client JSON for Hysteria2 E2E.
func BuildHysteria2ClientConfig(cfg Hysteria2ConnectConfig) ([]byte, error) {
	inbound := map[string]any{
		"type":        "mixed",
		"tag":         "mixed-in",
		"listen":      "127.0.0.1",
		"listen_port": localMixedPort,
	}
	outbound := map[string]any{
		"type":        "hysteria2",
		"tag":         "proxy",
		"server":      cfg.ServerHost,
		"server_port": cfg.Port,
		"password":    cfg.Password,
		"tls":         buildHysteria2ClientTLS(cfg.Data),
	}
	if cfg.Data.ObfsPassword != "" {
		outbound["obfs"] = map[string]any{
			"type":     "salamander",
			"password": cfg.Data.ObfsPassword,
		}
	}
	if cfg.Data.UpMbps > 0 {
		outbound["up_mbps"] = cfg.Data.UpMbps
	}
	if cfg.Data.DownMbps > 0 {
		outbound["down_mbps"] = cfg.Data.DownMbps
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

func buildHysteria2ClientTLS(data hysteria2.ProtocolData) map[string]any {
	tls := map[string]any{"enabled": true, "insecure": true}
	if data.ServerName != "" {
		tls["server_name"] = data.ServerName
	}
	alpn := data.ALPN
	if len(alpn) == 0 {
		alpn = append([]string{}, hysteria2.DefaultALPN...)
	}
	tls["alpn"] = alpn
	return tls
}

// CheckHysteria2ClientConfig validates a Hysteria2 client sing-box config on the client container.
func (r *Runner) CheckHysteria2ClientConfig(cfg Hysteria2ConnectConfig) error {
	r.t.Helper()
	raw, err := BuildHysteria2ClientConfig(cfg)
	if err != nil {
		return err
	}
	return r.checkSingBoxConfig(raw)
}

// CurlViaHysteria2 runs sing-box on the client and fetches TargetURL through Hysteria2.
func (r *Runner) CurlViaHysteria2(cfg Hysteria2ConnectConfig) error {
	r.t.Helper()
	raw, err := BuildHysteria2ClientConfig(cfg)
	if err != nil {
		return err
	}
	return r.curlViaSingBoxConfig(raw)
}
