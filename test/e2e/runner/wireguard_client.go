package runner

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/wireguard"
)

// WGConnectConfig describes sing-box client settings for a WireGuard E2E case.
type WGConnectConfig struct {
	ServerHost       string
	Port             int
	ServerPublicKey  string
	ClientPrivateKey string
	ClientAddress    string
	MTU              int
	Keepalive        int
	PSK              string
	Reserved         []int
	RouteCIDRs       []string
}

// WGConnectConfigFromCreate builds client connect settings from a create result.
func WGConnectConfigFromCreate(result VPNCreateResult) (WGConnectConfig, error) {
	data, err := wireguard.ParseProtocolData(result.VPN.ProtocolData)
	if err != nil {
		return WGConnectConfig{}, err
	}
	clients := []domain.ClientConfig{{
		Name:     result.Client.Name,
		Username: result.Client.Username,
		Password: result.Client.Password,
		Enabled:  result.Client.Enabled,
	}}
	clientAddress, err := wireguard.ClientTunnelIP(data, clients, result.Client.Name)
	if err != nil {
		return WGConnectConfig{}, err
	}
	mtu := data.MTU
	if mtu == 0 {
		mtu = wireguard.DefaultMTU
	}
	keepalive := data.PeerPersistentKeepaliveInterval
	if keepalive == 0 {
		keepalive = wireguard.DefaultPeerKeepalive
	}
	cfg := WGConnectConfig{
		ServerHost:       ServerHost,
		Port:             result.VPN.Listen.ListenPort,
		ServerPublicKey:  data.PublicKey,
		ClientPrivateKey: result.Client.Password,
		ClientAddress:    clientAddress,
		MTU:              mtu,
		Keepalive:        keepalive,
		PSK:              data.PeerPreSharedKey,
		Reserved:         append([]int(nil), data.PeerReserved...),
	}
	if cfg.ServerPublicKey == "" {
		return WGConnectConfig{}, fmt.Errorf("empty server public key in protocol data")
	}
	if cfg.ClientPrivateKey == "" {
		return WGConnectConfig{}, fmt.Errorf("empty client private key")
	}
	return cfg, nil
}

// BuildWGClientConfig renders a sing-box client JSON for WireGuard E2E.
func BuildWGClientConfig(cfg WGConnectConfig) ([]byte, error) {
	if len(cfg.RouteCIDRs) == 0 {
		return nil, fmt.Errorf("empty route CIDRs")
	}
	peer := map[string]any{
		"address":                       cfg.ServerHost,
		"port":                          cfg.Port,
		"public_key":                    cfg.ServerPublicKey,
		"allowed_ips":                   append([]string{}, cfg.RouteCIDRs...),
		"persistent_keepalive_interval": cfg.Keepalive,
	}
	if cfg.PSK != "" {
		peer["pre_shared_key"] = cfg.PSK
	}
	if len(cfg.Reserved) == 3 {
		peer["reserved"] = cfg.Reserved
	}
	endpoint := map[string]any{
		"type":        "wireguard",
		"tag":         "wg-ep",
		"system":      false,
		"address":     []string{cfg.ClientAddress},
		"private_key": cfg.ClientPrivateKey,
		"mtu":         cfg.MTU,
		"peers":       []map[string]any{peer},
	}
	config := map[string]any{
		"endpoints": []map[string]any{endpoint},
		"route": map[string]any{
			"final":                 "direct",
			"auto_detect_interface": true,
		},
	}
	return json.Marshal(config)
}

// ResolveHostIP resolves a hostname to an IPv4 address inside the client container.
func (r *Runner) ResolveHostIP(host string) (string, error) {
	r.t.Helper()
	out, err := r.clientExec("getent", "hosts", host)
	if err != nil {
		return "", fmt.Errorf("resolve %q: %w", host, err)
	}
	fields := strings.Fields(out)
	if len(fields) == 0 {
		return "", fmt.Errorf("resolve %q: empty getent output", host)
	}
	return fields[0], nil
}

// CurlViaWireguard runs sing-box on the client and fetches TargetURL through the WG tunnel.
func (r *Runner) CurlViaWireguard(cfg WGConnectConfig) error {
	r.t.Helper()
	raw, err := BuildWGClientConfig(cfg)
	if err != nil {
		return err
	}
	return r.curlViaWireguardConfig(raw)
}

func (r *Runner) curlViaWireguardConfig(raw []byte) error {
	r.t.Helper()
	b64 := base64.StdEncoding.EncodeToString(raw)
	script := fmt.Sprintf(`set -euo pipefail
if command -v pkill >/dev/null 2>&1; then pkill -f 'sing-box run -c /tmp/sb-e2e-wg.json' 2>/dev/null || true; fi
sleep 0.5
echo %q | base64 -d >/tmp/sb-e2e-wg.json
sing-box check -c /tmp/sb-e2e-wg.json
sing-box run -c /tmp/sb-e2e-wg.json & pid=$!
trap 'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true' EXIT
sleep 3
for i in 1 2 3; do
  if curl -sf --max-time 15 %q; then
    exit 0
  fi
  sleep 2
done
exit 1`, b64, TargetURL)
	_, err := r.clientExec("bash", "-c", script)
	return err
}
