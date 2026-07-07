package runner

import (
	"encoding/json"
	"fmt"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/shadowsocks"
)

const localMixedPort = 18080

// VPNCreateResult is the parsed obscura vpn create --json response.
type VPNCreateResult struct {
	URI    string
	Client domain.Client
	VPN    domain.VPN
}

// SSConnectConfig describes sing-box client settings for a Shadowsocks E2E case.
type SSConnectConfig struct {
	ServerHost             string
	Port                   int
	Method                 string
	ServerPassword         string
	Password               string
	Multiplex              bool
	MultiplexPadding       bool
	ShadowTLS              bool
	ShadowTLSPassword      string
	ShadowTLSHandshake     string
	ShadowTLSHandshakePort int
}

// CreateVPNFull runs obscura vpn create and returns the full JSON payload.
func (r *Runner) CreateVPNFull(name, protocol string, port int, extra ...string) (VPNCreateResult, error) {
	r.t.Helper()
	r.resetSingBoxUnit()
	args := []string{
		"--name", name,
		"--protocol", protocol,
		"--port", fmt.Sprintf("%d", port),
		"--client-host", ServerHost,
		"--client-name", ClientName,
	}
	args = append(args, extra...)
	out, err := r.serverExec(nil, append([]string{"obscura", "vpn", "create"}, append(args, "--json")...)...)
	if err != nil {
		return VPNCreateResult{}, err
	}
	var resp struct {
		URI    string        `json:"uri"`
		Client domain.Client `json:"client"`
		VPN    domain.VPN    `json:"vpn"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return VPNCreateResult{}, fmt.Errorf("parse vpn create json: %w\noutput: %s", err, out)
	}
	if resp.URI == "" {
		return VPNCreateResult{}, fmt.Errorf("empty uri in create output: %s", out)
	}
	return VPNCreateResult{URI: resp.URI, Client: resp.Client, VPN: resp.VPN}, nil
}

// SSConnectConfigFromCreate builds client connect settings from a create result.
func SSConnectConfigFromCreate(result VPNCreateResult, multiplex, multiplexPadding bool) (SSConnectConfig, error) {
	data, err := shadowsocks.ParseProtocolData(result.VPN.ProtocolData)
	if err != nil {
		return SSConnectConfig{}, err
	}
	cfg := SSConnectConfig{
		ServerHost:             ServerHost,
		Port:                   result.VPN.Listen.ListenPort,
		Method:                 data.Method,
		ServerPassword:         data.ServerPassword,
		Password:               result.Client.Password,
		Multiplex:              multiplex,
		MultiplexPadding:       multiplexPadding,
		ShadowTLS:              data.ShadowTLS,
		ShadowTLSPassword:      data.ShadowTLSPassword,
		ShadowTLSHandshake:     data.ShadowTLSHandshake,
		ShadowTLSHandshakePort: data.ShadowTLSHandshakePort,
	}
	if cfg.Method == "" {
		return SSConnectConfig{}, fmt.Errorf("empty shadowsocks method in protocol data")
	}
	if cfg.ServerPassword == "" {
		return SSConnectConfig{}, fmt.Errorf("empty server password in protocol data")
	}
	if cfg.Password == "" {
		return SSConnectConfig{}, fmt.Errorf("empty client password")
	}
	if cfg.ShadowTLS && cfg.ShadowTLSPassword == "" {
		return SSConnectConfig{}, fmt.Errorf("empty shadowtls password in protocol data")
	}
	return cfg, nil
}

// BuildSSClientConfig renders a sing-box client JSON for Shadowsocks E2E.
func BuildSSClientConfig(cfg SSConnectConfig) ([]byte, error) {
	inbound := map[string]any{
		"type":        "mixed",
		"tag":         "mixed-in",
		"listen":      "127.0.0.1",
		"listen_port": localMixedPort,
	}
	outbounds := []map[string]any{
		{"type": "direct", "tag": "direct"},
		{"type": "block", "tag": "block"},
	}

	ssOutbound := map[string]any{
		"type":     "shadowsocks",
		"tag":      "proxy",
		"method":   cfg.Method,
		"password": cfg.ServerPassword + ":" + cfg.Password,
	}
	if cfg.Multiplex && !cfg.ShadowTLS {
		ssOutbound["multiplex"] = multiplexOptions(cfg.MultiplexPadding)
	}

	if cfg.ShadowTLS {
		stTag := "shadowtls-out"
		ssOutbound["detour"] = stTag
		handshakeServer := cfg.ShadowTLSHandshake
		if handshakeServer == "" {
			handshakeServer = shadowsocks.DefaultShadowTLSHandshake
		}
		handshakePort := cfg.ShadowTLSHandshakePort
		if handshakePort == 0 {
			handshakePort = shadowsocks.DefaultShadowTLSHandshakePort
		}
		stOutbound := map[string]any{
			"type":        "shadowtls",
			"tag":         stTag,
			"server":      cfg.ServerHost,
			"server_port": cfg.Port,
			"version":     3,
			"password":    cfg.ShadowTLSPassword,
			"tls": map[string]any{
				"enabled":     true,
				"server_name": handshakeServer,
				"insecure":    true,
				"utls": map[string]any{
					"enabled":     true,
					"fingerprint": "chrome",
				},
			},
		}
		_ = handshakePort // Server-side handshake port; client uses tls.server_name only.
		outbounds = append(outbounds, ssOutbound, stOutbound)
	} else {
		ssOutbound["server"] = cfg.ServerHost
		ssOutbound["server_port"] = cfg.Port
		outbounds = append(outbounds, ssOutbound)
	}

	config := map[string]any{
		"inbounds":  []map[string]any{inbound},
		"outbounds": outbounds,
		"route":     map[string]any{"final": "proxy"},
	}
	return json.Marshal(config)
}

// alpnForTransport returns the ALPN list to advertise for the given transport.
// HTTPUpgrade requires HTTP/1.1; h2 breaks connection hijacking.
// Falls back to defaultALPN for all other transports.
func alpnForTransport(transportType string, defaultALPN []string) []string {
	if transportType == "httpupgrade" {
		return []string{"http/1.1"}
	}
	return defaultALPN
}

func multiplexOptions(padding bool) map[string]any {
	m := map[string]any{"enabled": true}
	if padding {
		m["padding"] = true
	}
	return m
}

// CurlViaShadowsocks runs sing-box on the client and fetches TargetURL through SS/ShadowTLS.
func (r *Runner) CurlViaShadowsocks(cfg SSConnectConfig) error {
	r.t.Helper()
	raw, err := BuildSSClientConfig(cfg)
	if err != nil {
		return err
	}
	return r.curlViaSingBoxConfig(raw)
}
