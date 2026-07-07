package cmd_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/httpproxy"
	"github.com/ivan-khludov/obscura/internal/protocol/hysteria2"
	"github.com/ivan-khludov/obscura/internal/protocol/shadowsocks"
	"github.com/ivan-khludov/obscura/internal/protocol/trojan"
	"github.com/ivan-khludov/obscura/internal/protocol/tuic"
	"github.com/ivan-khludov/obscura/internal/protocol/vless"
	"github.com/ivan-khludov/obscura/internal/protocol/vmess"
	"github.com/ivan-khludov/obscura/internal/protocol/wireguard"
)

func TestVPNCreateJSON(t *testing.T) {
	root, ctx := newTestRoot(t)
	out := runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "create", "--name", "main", "--port", "1080", "--client-name", "phone")
	var result struct {
		VPN    map[string]any `json:"vpn"`
		Client map[string]any `json:"client"`
		URI    string         `json:"uri"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if result.VPN == nil || result.VPN["Name"] != "main" {
		t.Fatalf("unexpected vpn: %#v", result.VPN)
	}
	if result.Client == nil || result.Client["Name"] != "phone" {
		t.Fatalf("unexpected client: %#v", result.Client)
	}
	if !strings.HasPrefix(result.URI, "socks5://") {
		t.Fatalf("unexpected uri: %q", result.URI)
	}
}

func TestVPNCreateHTTPJSON(t *testing.T) {
	root, ctx := newTestRoot(t)
	out := runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "create", "--name", "web", "--protocol", "http", "--port", "8080", "--client-name", "phone")
	var result struct {
		VPN    map[string]any `json:"vpn"`
		Client map[string]any `json:"client"`
		URI    string         `json:"uri"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if result.VPN == nil || result.VPN["Protocol"] != "http" {
		t.Fatalf("unexpected vpn: %#v", result.VPN)
	}
	if !strings.HasPrefix(result.URI, "http://") {
		t.Fatalf("unexpected uri: %q", result.URI)
	}
}

func TestVPNEditTLSJSON(t *testing.T) {
	root, ctx := newTestRoot(t)
	runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "create", "--name", "web", "--protocol", "http", "--port", "8080", "--client-name", "phone")
	out := runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "edit", "web", "--tls")
	var vpn domain.VPN
	if err := json.Unmarshal([]byte(out), &vpn); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	data, err := httpproxy.ParseProtocolData(vpn.ProtocolData)
	if err != nil || !data.TLS {
		t.Fatalf("expected tls enabled, got %#v err=%v", data, err)
	}
}

func TestVPNEditNoTLSText(t *testing.T) {
	root, ctx := newTestRoot(t)
	runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "create", "--name", "web", "--protocol", "http", "--port", "8080", "--client-name", "phone", "--tls")
	out, err := runCommand(t, root, ctx, "--dev", "vpn", "edit", "web", "--no-tls", "--apply=false")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Protocol") {
		t.Fatalf("unexpected output: %q", out)
	}
}

func TestVPNEditDisabledAndListenFlags(t *testing.T) {
	root, ctx := newTestRoot(t)
	runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "create", "--name", "main", "--port", "1080", "--client-name", "phone")
	out := runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "edit", "main",
		"--disabled", "--listen", "127.0.0.1", "--port", "1090", "--apply=false")
	var vpn domain.VPN
	if err := json.Unmarshal([]byte(out), &vpn); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if vpn.Enabled {
		t.Fatal("expected disabled vpn")
	}
	if vpn.Listen.Listen != "127.0.0.1" || vpn.Listen.ListenPort != 1090 {
		t.Fatalf("unexpected listen: %#v", vpn.Listen)
	}
}

func TestVPNCreateShadowsocksJSON(t *testing.T) {
	root, ctx := newTestRoot(t)
	out := runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "create",
		"--name", "ss", "--protocol", "shadowsocks", "--method", "2022-blake3-aes-128-gcm",
		"--port", "8388", "--client-name", "phone")
	var result struct {
		VPN    map[string]any `json:"vpn"`
		Client map[string]any `json:"client"`
		URI    string         `json:"uri"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if result.VPN == nil || result.VPN["Protocol"] != "shadowsocks" {
		t.Fatalf("unexpected vpn: %#v", result.VPN)
	}
	if !strings.HasPrefix(result.URI, "ss://") {
		t.Fatalf("unexpected uri: %q", result.URI)
	}
}

func TestVPNCreateShadowsocksMultiplexJSON(t *testing.T) {
	root, ctx := newTestRoot(t)
	out := runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "create",
		"--name", "ss", "--protocol", "shadowsocks", "--port", "8388",
		"--multiplex", "--multiplex-padding", "--client-name", "phone")
	var result struct {
		VPN map[string]any `json:"vpn"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	raw, ok := result.VPN["ProtocolData"].(string)
	if !ok {
		t.Fatalf("expected ProtocolData string, got %#v", result.VPN["ProtocolData"])
	}
	protocolBytes, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	data, err := shadowsocks.ParseProtocolData(protocolBytes)
	if err != nil || !data.Multiplex || !data.MultiplexPadding {
		t.Fatalf("expected multiplex in protocol data: %#v err=%v", data, err)
	}
}

func TestVPNCreateShadowsocksPluginJSON(t *testing.T) {
	root, ctx := newTestRoot(t)
	out := runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "create",
		"--name", "ss", "--protocol", "shadowsocks", "--port", "8388",
		"--plugin", "obfs-local", "--plugin-opts", shadowsocks.DefaultObfsPluginOpts,
		"--client-name", "phone")
	var result struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if !strings.Contains(result.URI, "plugin=obfs-local") {
		t.Fatalf("expected plugin in uri: %q", result.URI)
	}
}

func TestVPNCreateTrojanJSON(t *testing.T) {
	root, ctx := newTestRoot(t)
	out := runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "create",
		"--name", "tr", "--protocol", "trojan", "--port", "443",
		"--tls-server-name", "example.com", "--multiplex", "--transport", "ws",
		"--transport-path", "/video", "--client-name", "phone")
	var result struct {
		VPN map[string]any `json:"vpn"`
		URI string         `json:"uri"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if result.VPN == nil || result.VPN["Protocol"] != "trojan" {
		t.Fatalf("unexpected vpn: %#v", result.VPN)
	}
	raw, ok := result.VPN["ProtocolData"].(string)
	if !ok {
		t.Fatalf("expected ProtocolData string, got %#v", result.VPN["ProtocolData"])
	}
	protocolBytes, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	data, err := trojan.ParseProtocolData(protocolBytes)
	if err != nil || data.ServerName != "example.com" || !data.Multiplex || data.TransportType != "ws" {
		t.Fatalf("unexpected protocol data: %#v err=%v", data, err)
	}
	if !strings.HasPrefix(result.URI, "trojan://") {
		t.Fatalf("unexpected uri: %q", result.URI)
	}
}

func TestVPNCreateVmessJSON(t *testing.T) {
	root, ctx := newTestRoot(t)
	out := runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "create",
		"--name", "vm", "--protocol", "vmess", "--port", "443",
		"--tls-server-name", "example.com", "--multiplex", "--transport", "ws",
		"--transport-path", "/video", "--client-name", "phone")
	var result struct {
		VPN map[string]any `json:"vpn"`
		URI string         `json:"uri"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if result.VPN == nil || result.VPN["Protocol"] != "vmess" {
		t.Fatalf("unexpected vpn: %#v", result.VPN)
	}
	raw, ok := result.VPN["ProtocolData"].(string)
	if !ok {
		t.Fatalf("expected ProtocolData string, got %#v", result.VPN["ProtocolData"])
	}
	protocolBytes, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	data, err := vmess.ParseProtocolData(protocolBytes)
	if err != nil || data.ServerName != "example.com" || !data.Multiplex || data.TransportType != "ws" {
		t.Fatalf("unexpected protocol data: %#v err=%v", data, err)
	}
	if !strings.HasPrefix(result.URI, "vmess://") {
		t.Fatalf("unexpected uri: %q", result.URI)
	}
}

func TestVPNCreateVlessJSON(t *testing.T) {
	root, ctx := newTestRoot(t)
	out := runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "create",
		"--name", "vl", "--protocol", "vless", "--port", "443",
		"--tls-server-name", "example.com", "--multiplex",
		"--client-name", "phone")
	var result struct {
		VPN map[string]any `json:"vpn"`
		URI string         `json:"uri"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if result.VPN == nil || result.VPN["Protocol"] != "vless" {
		t.Fatalf("unexpected vpn: %#v", result.VPN)
	}
	raw, ok := result.VPN["ProtocolData"].(string)
	if !ok {
		t.Fatalf("expected ProtocolData string, got %#v", result.VPN["ProtocolData"])
	}
	protocolBytes, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	data, err := vless.ParseProtocolData(protocolBytes)
	if err != nil || data.ServerName != "example.com" || !data.Multiplex {
		t.Fatalf("unexpected protocol data: %#v err=%v", data, err)
	}
	if !strings.HasPrefix(result.URI, "vless://") {
		t.Fatalf("unexpected uri: %q", result.URI)
	}
}

func TestVPNCreateHysteria2JSON(t *testing.T) {
	root, ctx := newTestRoot(t)
	out := runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "create",
		"--name", "hy", "--protocol", "hysteria2", "--port", "443",
		"--hy2-tls-server-name", "example.com", "--hy2-obfs-password", "obfs-secret",
		"--hy2-up-mbps", "100", "--hy2-down-mbps", "100",
		"--client-name", "phone")
	var result struct {
		VPN map[string]any `json:"vpn"`
		URI string         `json:"uri"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if result.VPN == nil || result.VPN["Protocol"] != "hysteria2" {
		t.Fatalf("unexpected vpn: %#v", result.VPN)
	}
	raw, ok := result.VPN["ProtocolData"].(string)
	if !ok {
		t.Fatalf("expected ProtocolData string, got %#v", result.VPN["ProtocolData"])
	}
	protocolBytes, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	data, err := hysteria2.ParseProtocolData(protocolBytes)
	if err != nil || data.ServerName != "example.com" || data.ObfsPassword != "obfs-secret" || data.UpMbps != 100 {
		t.Fatalf("unexpected protocol data: %#v err=%v", data, err)
	}
	if !strings.HasPrefix(result.URI, "hysteria2://") {
		t.Fatalf("unexpected uri: %q", result.URI)
	}
}

func TestVPNCreateTUICJSON(t *testing.T) {
	root, ctx := newTestRoot(t)
	out := runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "create",
		"--name", "tc", "--protocol", "tuic", "--port", "443",
		"--tuic-tls-server-name", "example.com", "--tuic-congestion-control", "bbr",
		"--client-name", "phone")
	var result struct {
		VPN map[string]any `json:"vpn"`
		URI string         `json:"uri"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if result.VPN == nil || result.VPN["Protocol"] != "tuic" {
		t.Fatalf("unexpected vpn: %#v", result.VPN)
	}
	raw, ok := result.VPN["ProtocolData"].(string)
	if !ok {
		t.Fatalf("expected ProtocolData string, got %#v", result.VPN["ProtocolData"])
	}
	protocolBytes, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	data, err := tuic.ParseProtocolData(protocolBytes)
	if err != nil || data.ServerName != "example.com" || data.CongestionControl != "bbr" {
		t.Fatalf("unexpected protocol data: %#v err=%v", data, err)
	}
	if !strings.HasPrefix(result.URI, "tuic://") {
		t.Fatalf("unexpected uri: %q", result.URI)
	}
}

func TestVPNCreateWireguardJSON(t *testing.T) {
	root, ctx := newTestRoot(t)
	out := runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "create",
		"--name", "wg", "--protocol", "wireguard", "--port", "51820",
		"--wg-address", "10.8.0.1/24", "--wg-mtu", "1420", "--client-name", "phone")
	var result struct {
		VPN map[string]any `json:"vpn"`
		URI string         `json:"uri"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if result.VPN == nil || result.VPN["Protocol"] != "wireguard" {
		t.Fatalf("unexpected vpn: %#v", result.VPN)
	}
	raw, ok := result.VPN["ProtocolData"].(string)
	if !ok {
		t.Fatalf("expected ProtocolData string, got %#v", result.VPN["ProtocolData"])
	}
	protocolBytes, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	data, err := wireguard.ParseProtocolData(protocolBytes)
	if err != nil || data.MTU != 1420 || len(data.Address) != 1 {
		t.Fatalf("unexpected protocol data: %#v err=%v", data, err)
	}
	if !strings.HasPrefix(result.URI, "wireguard://") {
		t.Fatalf("unexpected uri: %q", result.URI)
	}
}

func TestVPNCreateClientHostJSON(t *testing.T) {
	root, ctx := newTestRoot(t)
	out := runJSONCommand(t, root, ctx,
		"vpn", "create",
		"--name", "hy",
		"--protocol", "hysteria2",
		"--port", "20783",
		"--client-host", "culhackervpn.duckdns.org",
		"--hy2-tls-server-name", "culhackervpn.duckdns.org",
		"--client-name", "phone",
		"--json",
	)
	var result struct {
		VPN map[string]any `json:"vpn"`
		URI string         `json:"uri"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if result.VPN["ClientHost"] != "culhackervpn.duckdns.org" {
		t.Fatalf("client_host = %v", result.VPN["ClientHost"])
	}
	if !strings.Contains(result.URI, "culhackervpn.duckdns.org:20783") {
		t.Fatalf("unexpected uri: %q", result.URI)
	}
	out = runJSONCommand(t, root, ctx, "vpn", "edit", "hy", "--clear-client-host", "--apply=false", "--json")
	var updated map[string]any
	if err := json.Unmarshal([]byte(out), &updated); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if updated["ClientHost"] != "" {
		t.Fatalf("expected cleared client_host, got %v", updated["ClientHost"])
	}
}

func TestVPNCreateWithoutPort(t *testing.T) {
	root, ctx := newTestRoot(t)
	out := runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "create", "--name", "auto", "--client-name", "phone")
	var result struct {
		VPN map[string]any `json:"vpn"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if result.VPN["Name"] != "auto" {
		t.Fatalf("unexpected vpn: %#v", result.VPN)
	}
}

func TestVPNListShowDelete(t *testing.T) {
	root, ctx := newTestRoot(t)
	runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "create", "--name", "main", "--port", "1080", "--client-name", "phone")

	listOut := runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "list")
	var items []map[string]any
	if err := json.Unmarshal([]byte(listOut), &items); err != nil {
		t.Fatalf("invalid list json: %v\nout=%q", err, listOut)
	}
	if len(items) != 1 || items[0]["Name"] != "main" {
		t.Fatalf("unexpected list: %#v", items)
	}

	showOut := runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "show", "main")
	var vpn map[string]any
	if err := json.Unmarshal([]byte(showOut), &vpn); err != nil {
		t.Fatalf("invalid show json: %v\nout=%q", err, showOut)
	}
	if vpn["Name"] != "main" {
		t.Fatalf("unexpected show: %#v", vpn)
	}

	root.SetArgs([]string{"--dev", "vpn", "delete", "main"})
	if err := root.ExecuteContext(ctx); err != nil {
		t.Fatalf("delete vpn: %v", err)
	}
}

func TestVPNCreateWithFallbackStub(t *testing.T) {
	root, ctx := newTestRoot(t)
	out := runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "create",
		"--name", "tr", "--protocol", "trojan", "--port", "443",
		"--tls-server-name", "example.com", "--fallback-stub", "--client-name", "phone")
	var result struct {
		VPN map[string]any `json:"vpn"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if result.VPN["Protocol"] != "trojan" {
		t.Fatalf("unexpected vpn: %#v", result.VPN)
	}
}

func TestVPNEditRenameEnabled(t *testing.T) {
	root, ctx := newTestRoot(t)
	runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "create", "--name", "main", "--port", "1080", "--client-name", "phone")
	out := runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "edit", "main", "--new-name", "renamed", "--enabled", "--apply=false")
	var vpn domain.VPN
	if err := json.Unmarshal([]byte(out), &vpn); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if vpn.Name != "renamed" || !vpn.Enabled {
		t.Fatalf("unexpected vpn: %#v", vpn)
	}
}
