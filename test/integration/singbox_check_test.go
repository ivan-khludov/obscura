//go:build integration

package integration_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ivan-khludov/obscura/internal/certs"
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/hysteria2"
	"github.com/ivan-khludov/obscura/internal/protocol/shadowsocks"
	"github.com/ivan-khludov/obscura/internal/protocol/trojan"
	"github.com/ivan-khludov/obscura/internal/protocol/tuic"
	"github.com/ivan-khludov/obscura/internal/protocol/vless"
	"github.com/ivan-khludov/obscura/internal/protocol/vmess"
	"github.com/ivan-khludov/obscura/internal/protocol/wireguard"
	"github.com/ivan-khludov/obscura/internal/render"
	"github.com/ivan-khludov/obscura/internal/runtime"
	"github.com/ivan-khludov/obscura/internal/store"
)

// TestSingBoxCheckGeneratedConfig validates rendered config with sing-box check.
func TestSingBoxCheckGeneratedConfig(t *testing.T) {
	if _, err := exec.LookPath("sing-box"); err != nil {
		t.Skip("sing-box not installed")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	cfgPath := filepath.Join(dir, "sing-box.json")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	vpn := &domain.VPN{
		Name: "main", Protocol: "socks5", Tag: "vpn-main", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080},
	}
	if err := st.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	client := &domain.Client{
		VPNID: vpn.ID, Name: "phone", Username: "phone", Password: "secret", Enabled: true,
	}
	if err := st.CreateClient(ctx, client); err != nil {
		t.Fatal(err)
	}
	r := render.NewRenderer(st, runtime.NewProtocolRegistry())
	raw, err := r.Render(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "sing-box", "check", "-c", cfgPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check: %v: %s", err, out)
	}
}

// TestSingBoxCheckHTTPInbound validates rendered HTTP proxy config with sing-box check.
func TestSingBoxCheckHTTPInbound(t *testing.T) {
	if _, err := exec.LookPath("sing-box"); err != nil {
		t.Skip("sing-box not installed")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	cfgPath := filepath.Join(dir, "sing-box.json")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	vpn := &domain.VPN{
		Name: "web", Protocol: "http", Tag: "vpn-web", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8080},
	}
	if err := st.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	client := &domain.Client{
		VPNID: vpn.ID, Name: "phone", Username: "phone", Password: "secret", Enabled: true,
	}
	if err := st.CreateClient(ctx, client); err != nil {
		t.Fatal(err)
	}
	r := render.NewRenderer(st, runtime.NewProtocolRegistry())
	raw, err := r.Render(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "sing-box", "check", "-c", cfgPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check: %v: %s", err, out)
	}
}

// TestSingBoxCheckShadowsocksInbound validates rendered Shadowsocks config with sing-box check.
func TestSingBoxCheckShadowsocksInbound(t *testing.T) {
	if _, err := exec.LookPath("sing-box"); err != nil {
		t.Skip("sing-box not installed")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	cfgPath := filepath.Join(dir, "sing-box.json")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	protocolData, err := shadowsocks.MarshalProtocolData(shadowsocks.ProtocolData{
		Method:         "2022-blake3-aes-128-gcm",
		ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
	})
	if err != nil {
		t.Fatal(err)
	}
	vpn := &domain.VPN{
		Name: "ss", Protocol: "shadowsocks", Tag: "vpn-ss", Enabled: true,
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8388},
		ProtocolData: protocolData,
	}
	if err := st.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	client := &domain.Client{
		VPNID: vpn.ID, Name: "phone", Username: "phone", Password: "PCD2Z4o12bKUoFa3cC97Hw==", Enabled: true,
	}
	if err := st.CreateClient(ctx, client); err != nil {
		t.Fatal(err)
	}
	r := render.NewRenderer(st, runtime.NewProtocolRegistry())
	raw, err := r.Render(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "sing-box", "check", "-c", cfgPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check: %v: %s", err, out)
	}
}

// TestSingBoxCheckShadowsocksShadowTLS validates ShadowTLS + Shadowsocks config with sing-box check.
func TestSingBoxCheckShadowsocksShadowTLS(t *testing.T) {
	if _, err := exec.LookPath("sing-box"); err != nil {
		t.Skip("sing-box not installed")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	cfgPath := filepath.Join(dir, "sing-box.json")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	protocolData, err := shadowsocks.MarshalProtocolData(shadowsocks.ProtocolData{
		Method: "2022-blake3-aes-128-gcm", ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
		ShadowTLS: true, ShadowTLSPassword: "st-secret", ShadowTLSHandshake: "www.bing.com",
		ShadowTLSBackendPort: 38443,
	})
	if err != nil {
		t.Fatal(err)
	}
	vpn := &domain.VPN{
		Name: "ss-st", Protocol: "shadowsocks", Tag: "vpn-ss-st", Enabled: true,
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: protocolData,
	}
	if err := st.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	client := &domain.Client{
		VPNID: vpn.ID, Name: "phone", Username: "phone", Password: "PCD2Z4o12bKUoFa3cC97Hw==", Enabled: true,
	}
	if err := st.CreateClient(ctx, client); err != nil {
		t.Fatal(err)
	}
	r := render.NewRenderer(st, runtime.NewProtocolRegistry())
	raw, err := r.Render(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "sing-box", "check", "-c", cfgPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check: %v: %s", err, out)
	}
}

// TestSingBoxCheckShadowsocksMultiplex validates multiplex padding on Shadowsocks inbound.
func TestSingBoxCheckShadowsocksMultiplex(t *testing.T) {
	if _, err := exec.LookPath("sing-box"); err != nil {
		t.Skip("sing-box not installed")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	cfgPath := filepath.Join(dir, "sing-box.json")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	protocolData, err := shadowsocks.MarshalProtocolData(shadowsocks.ProtocolData{
		Method: "2022-blake3-aes-128-gcm", ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
		Multiplex: true, MultiplexPadding: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	vpn := &domain.VPN{
		Name: "ss-mux", Protocol: "shadowsocks", Tag: "vpn-ss-mux", Enabled: true,
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8388},
		ProtocolData: protocolData,
	}
	if err := st.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	client := &domain.Client{
		VPNID: vpn.ID, Name: "phone", Username: "phone", Password: "PCD2Z4o12bKUoFa3cC97Hw==", Enabled: true,
	}
	if err := st.CreateClient(ctx, client); err != nil {
		t.Fatal(err)
	}
	r := render.NewRenderer(st, runtime.NewProtocolRegistry())
	raw, err := r.Render(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "sing-box", "check", "-c", cfgPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check: %v: %s", err, out)
	}
}

// TestSingBoxCheckTrojanInbound validates rendered Trojan config with sing-box check.
func TestSingBoxCheckTrojanInbound(t *testing.T) {
	if _, err := exec.LookPath("sing-box"); err != nil {
		t.Skip("sing-box not installed")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	cfgPath := filepath.Join(dir, "sing-box.json")
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	if err := certs.GenerateSelfSigned("example.com", certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	protocolData, err := trojan.MarshalProtocolData(trojan.ProtocolData{
		CertPath: certPath, KeyPath: keyPath, ServerName: "example.com",
		ALPN: []string{"h2", "http/1.1"}, Multiplex: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	vpn := &domain.VPN{
		Name: "tr", Protocol: "trojan", Tag: "vpn-tr", Enabled: true,
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: protocolData,
	}
	if err := st.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	client := &domain.Client{
		VPNID: vpn.ID, Name: "phone", Username: "phone", Password: "secret", Enabled: true,
	}
	if err := st.CreateClient(ctx, client); err != nil {
		t.Fatal(err)
	}
	r := render.NewRenderer(st, runtime.NewProtocolRegistry())
	raw, err := r.Render(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "sing-box", "check", "-c", cfgPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check: %v: %s", err, out)
	}
}

// TestSingBoxCheckVmessInbound validates rendered VMess config with sing-box check.
func TestSingBoxCheckVmessInbound(t *testing.T) {
	if _, err := exec.LookPath("sing-box"); err != nil {
		t.Skip("sing-box not installed")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	cfgPath := filepath.Join(dir, "sing-box.json")
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	if err := certs.GenerateSelfSigned("example.com", certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	protocolData, err := vmess.MarshalProtocolData(vmess.ProtocolData{
		CertPath: certPath, KeyPath: keyPath, ServerName: "example.com",
		ALPN: []string{"h2", "http/1.1"}, Multiplex: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	vpn := &domain.VPN{
		Name: "vm", Protocol: "vmess", Tag: "vpn-vm", Enabled: true,
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: protocolData,
	}
	if err := st.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	client := &domain.Client{
		VPNID: vpn.ID, Name: "phone", Username: "", Password: "550e8400-e29b-41d4-a716-446655440000", Enabled: true,
	}
	if err := st.CreateClient(ctx, client); err != nil {
		t.Fatal(err)
	}
	r := render.NewRenderer(st, runtime.NewProtocolRegistry())
	raw, err := r.Render(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "sing-box", "check", "-c", cfgPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check: %v: %s", err, out)
	}
}

// TestSingBoxCheckVmessAllExtendedOptions validates extended VMess TLS/transport options with sing-box check.
func TestSingBoxCheckVmessAllExtendedOptions(t *testing.T) {
	if _, err := exec.LookPath("sing-box"); err != nil {
		t.Skip("sing-box not installed")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	cfgPath := filepath.Join(dir, "sing-box.json")
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	if err := certs.GenerateSelfSigned("example.com", certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	echKeyPath := filepath.Join(dir, "ech.key")
	if _, err := vmess.GenerateECHKeypair("sing-box", "example.com", echKeyPath); err != nil {
		t.Fatal(err)
	}
	extData, err := vmess.MarshalProtocolData(vmess.ProtocolData{
		CertPath: certPath, KeyPath: keyPath, ServerName: "example.com",
		ALPN:       []string{"h2", "http/1.1"},
		MinVersion: "1.2", MaxVersion: "1.3", HandshakeTimeout: "5s",
		ECHEnabled: true, ECHKeyPath: echKeyPath,
		DefaultAlterId: 64,
		Multiplex:      true, MultiplexBrutal: true,
		MultiplexBrutalUpMbps: 100, MultiplexBrutalDownMbps: 100,
		TransportType: "ws",
		TransportWS: &vmess.TransportWS{
			Path: "/video", MaxEarlyData: 2048, EarlyDataHeaderName: "Sec-WebSocket-Protocol",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	acmeData, err := vmess.MarshalProtocolData(vmess.ProtocolData{
		ACME: &vmess.ACMEOptions{
			Domains: []string{"example.com"},
			Email:   "admin@example.com",
		},
		TransportType: "grpc",
		TransportGRPC: &vmess.TransportGRPC{
			ServiceName: "TunService", PermitWithoutStream: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	extVPN := &domain.VPN{
		Name: "vm-ext", Protocol: "vmess", Tag: "vpn-vm-ext", Enabled: true,
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: extData,
	}
	if err := st.CreateVPN(ctx, extVPN); err != nil {
		t.Fatal(err)
	}
	acmeVPN := &domain.VPN{
		Name: "vm-acme", Protocol: "vmess", Tag: "vpn-vm-acme", Enabled: true,
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8444},
		ProtocolData: acmeData,
	}
	if err := st.CreateVPN(ctx, acmeVPN); err != nil {
		t.Fatal(err)
	}
	for _, spec := range []struct {
		vpnID int64
		name  string
		uuid  string
	}{
		{extVPN.ID, "phone", "550e8400-e29b-41d4-a716-446655440000"},
		{acmeVPN.ID, "tablet", "660e8400-e29b-41d4-a716-446655440001"},
	} {
		client := &domain.Client{
			VPNID: spec.vpnID, Name: spec.name, Password: spec.uuid, Enabled: true,
		}
		if err := st.CreateClient(ctx, client); err != nil {
			t.Fatal(err)
		}
	}
	r := render.NewRenderer(st, runtime.NewProtocolRegistry())
	raw, err := r.Render(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "sing-box", "check", "-c", cfgPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check: %v: %s", err, out)
	}
}

// TestSingBoxCheckVlessAllExtendedOptions validates extended VLESS TLS/transport options with sing-box check.
func TestSingBoxCheckVlessAllExtendedOptions(t *testing.T) {
	if _, err := exec.LookPath("sing-box"); err != nil {
		t.Skip("sing-box not installed")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	cfgPath := filepath.Join(dir, "sing-box.json")
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	if err := certs.GenerateSelfSigned("example.com", certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	echKeyPath := filepath.Join(dir, "ech.key")
	if _, err := vless.GenerateECHKeypair("sing-box", "example.com", echKeyPath); err != nil {
		t.Fatal(err)
	}
	extData, err := vless.MarshalProtocolData(vless.ProtocolData{
		CertPath: certPath, KeyPath: keyPath, ServerName: "example.com",
		ALPN:       []string{"h2", "http/1.1"},
		MinVersion: "1.2", MaxVersion: "1.3", HandshakeTimeout: "5s",
		ECHEnabled: true, ECHKeyPath: echKeyPath,
		Multiplex: true, MultiplexBrutal: true,
		MultiplexBrutalUpMbps: 100, MultiplexBrutalDownMbps: 100,
		TransportType: "ws",
		TransportWS: &vless.TransportWS{
			Path: "/video", MaxEarlyData: 2048, EarlyDataHeaderName: "Sec-WebSocket-Protocol",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	acmeData, err := vless.MarshalProtocolData(vless.ProtocolData{
		ACME: &vless.ACMEOptions{
			Domains: []string{"example.com"},
			Email:   "admin@example.com",
		},
		TransportType: "grpc",
		TransportGRPC: &vless.TransportGRPC{
			ServiceName: "TunService", PermitWithoutStream: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	extVPN := &domain.VPN{
		Name: "vl-ext", Protocol: "vless", Tag: "vpn-vl-ext", Enabled: true,
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: extData,
	}
	if err := st.CreateVPN(ctx, extVPN); err != nil {
		t.Fatal(err)
	}
	acmeVPN := &domain.VPN{
		Name: "vl-acme", Protocol: "vless", Tag: "vpn-vl-acme", Enabled: true,
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8444},
		ProtocolData: acmeData,
	}
	if err := st.CreateVPN(ctx, acmeVPN); err != nil {
		t.Fatal(err)
	}
	for _, spec := range []struct {
		vpnID int64
		name  string
		uuid  string
	}{
		{extVPN.ID, "phone", "550e8400-e29b-41d4-a716-446655440000"},
		{acmeVPN.ID, "tablet", "660e8400-e29b-41d4-a716-446655440001"},
	} {
		client := &domain.Client{
			VPNID: spec.vpnID, Name: spec.name, Password: spec.uuid, Enabled: true,
		}
		if err := st.CreateClient(ctx, client); err != nil {
			t.Fatal(err)
		}
	}
	r := render.NewRenderer(st, runtime.NewProtocolRegistry())
	raw, err := r.Render(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "sing-box", "check", "-c", cfgPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check: %v: %s", err, out)
	}
}

// TestSingBoxCheckVlessInbound validates rendered VLESS config with sing-box check.
func TestSingBoxCheckVlessInbound(t *testing.T) {
	if _, err := exec.LookPath("sing-box"); err != nil {
		t.Skip("sing-box not installed")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	cfgPath := filepath.Join(dir, "sing-box.json")
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	if err := certs.GenerateSelfSigned("example.com", certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	protocolData, err := vless.MarshalProtocolData(vless.ProtocolData{
		CertPath: certPath, KeyPath: keyPath, ServerName: "example.com",
		ALPN: []string{"h2", "http/1.1"}, Multiplex: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	vpn := &domain.VPN{
		Name: "vl", Protocol: "vless", Tag: "vpn-vl", Enabled: true,
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: protocolData,
	}
	if err := st.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	client := &domain.Client{
		VPNID: vpn.ID, Name: "phone", Password: "550e8400-e29b-41d4-a716-446655440000", Enabled: true,
	}
	if err := st.CreateClient(ctx, client); err != nil {
		t.Fatal(err)
	}
	r := render.NewRenderer(st, runtime.NewProtocolRegistry())
	raw, err := r.Render(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "sing-box", "check", "-c", cfgPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check: %v: %s", err, out)
	}
}

// TestSingBoxCheckHysteria2AllExtendedOptions validates extended Hysteria2 TLS/QUIC options with sing-box check.
func TestSingBoxCheckHysteria2AllExtendedOptions(t *testing.T) {
	if _, err := exec.LookPath("sing-box"); err != nil {
		t.Skip("sing-box not installed")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	cfgPath := filepath.Join(dir, "sing-box.json")
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	if err := certs.GenerateSelfSigned("example.com", certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	echKeyPath := filepath.Join(dir, "ech.key")
	if _, err := hysteria2.GenerateECHKeypair("sing-box", "example.com", echKeyPath); err != nil {
		t.Fatal(err)
	}
	extData, err := hysteria2.MarshalProtocolData(hysteria2.ProtocolData{
		CertPath: certPath, KeyPath: keyPath, ServerName: "example.com",
		ALPN:       []string{"h3"},
		MinVersion: "1.2", MaxVersion: "1.3", HandshakeTimeout: "5s",
		ECHEnabled: true, ECHKeyPath: echKeyPath,
		ObfsPassword: "obfs-secret",
		UpMbps:       100, DownMbps: 100,
		InitialPacketSize: 1200,
		HTTP2: &hysteria2.HTTP2Options{
			IdleTimeout: "30s", MaxConcurrentStreams: 100,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	acmeData, err := hysteria2.MarshalProtocolData(hysteria2.ProtocolData{
		ACME: &hysteria2.ACMEOptions{
			Domains: []string{"example.com"},
			Email:   "admin@example.com",
		},
		BBRProfile: hysteria2.BBRProfileStandard,
		Masquerade: &hysteria2.MasqueradeObject{
			Type:        hysteria2.MasqueradeTypeProxy,
			URL:         "http://127.0.0.1:8080",
			RewriteHost: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	extVPN := &domain.VPN{
		Name: "hy-ext", Protocol: "hysteria2", Tag: "vpn-hy-ext", Enabled: true,
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: extData,
	}
	if err := st.CreateVPN(ctx, extVPN); err != nil {
		t.Fatal(err)
	}
	acmeVPN := &domain.VPN{
		Name: "hy-acme", Protocol: "hysteria2", Tag: "vpn-hy-acme", Enabled: true,
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8444},
		ProtocolData: acmeData,
	}
	if err := st.CreateVPN(ctx, acmeVPN); err != nil {
		t.Fatal(err)
	}
	for _, spec := range []struct {
		vpnID int64
		name  string
		pass  string
	}{
		{extVPN.ID, "phone", "secret1"},
		{acmeVPN.ID, "tablet", "secret2"},
	} {
		client := &domain.Client{
			VPNID: spec.vpnID, Name: spec.name, Password: spec.pass, Enabled: true,
		}
		if err := st.CreateClient(ctx, client); err != nil {
			t.Fatal(err)
		}
	}
	r := render.NewRenderer(st, runtime.NewProtocolRegistry())
	raw, err := r.Render(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "sing-box", "check", "-c", cfgPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check: %v: %s", err, out)
	}
}

// TestSingBoxCheckHysteria2Inbound validates rendered Hysteria2 config with sing-box check.
func TestSingBoxCheckHysteria2Inbound(t *testing.T) {
	if _, err := exec.LookPath("sing-box"); err != nil {
		t.Skip("sing-box not installed")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	cfgPath := filepath.Join(dir, "sing-box.json")
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	if err := certs.GenerateSelfSigned("example.com", certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	protocolData, err := hysteria2.MarshalProtocolData(hysteria2.ProtocolData{
		CertPath: certPath, KeyPath: keyPath, ServerName: "example.com",
		ALPN: []string{"h3"}, ObfsPassword: "obfs-secret",
		UpMbps: 100, DownMbps: 100,
		MasqueradeURL: "http://127.0.0.1:8080",
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	vpn := &domain.VPN{
		Name: "hy", Protocol: "hysteria2", Tag: "vpn-hy", Enabled: true,
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: protocolData,
	}
	if err := st.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	client := &domain.Client{
		VPNID: vpn.ID, Name: "phone", Password: "secret", Enabled: true,
	}
	if err := st.CreateClient(ctx, client); err != nil {
		t.Fatal(err)
	}
	r := render.NewRenderer(st, runtime.NewProtocolRegistry())
	raw, err := r.Render(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "sing-box", "check", "-c", cfgPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check: %v: %s", err, out)
	}
}

// TestSingBoxCheckTUICAllExtendedOptions validates extended TUIC TLS/QUIC options with sing-box check.
func TestSingBoxCheckTUICAllExtendedOptions(t *testing.T) {
	if _, err := exec.LookPath("sing-box"); err != nil {
		t.Skip("sing-box not installed")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	cfgPath := filepath.Join(dir, "sing-box.json")
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	if err := certs.GenerateSelfSigned("example.com", certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	echKeyPath := filepath.Join(dir, "ech.key")
	if _, err := tuic.GenerateECHKeypair("sing-box", "example.com", echKeyPath); err != nil {
		t.Fatal(err)
	}
	extData, err := tuic.MarshalProtocolData(tuic.ProtocolData{
		CertPath: certPath, KeyPath: keyPath, ServerName: "example.com",
		ALPN:       []string{"h3"},
		MinVersion: "1.2", MaxVersion: "1.3", HandshakeTimeout: "5s",
		ECHEnabled: true, ECHKeyPath: echKeyPath,
		AuthTimeout: "3s", Heartbeat: "10s",
		InitialPacketSize: 1200,
		HTTP2: &tuic.HTTP2Options{
			IdleTimeout: "30s", MaxConcurrentStreams: 100,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	acmeData, err := tuic.MarshalProtocolData(tuic.ProtocolData{
		ACME: &tuic.ACMEOptions{
			Domains: []string{"example.com"},
			Email:   "admin@example.com",
		},
		CongestionControl: tuic.CongestionBBR,
		ZeroRTTHandshake:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	extVPN := &domain.VPN{
		Name: "tc-ext", Protocol: "tuic", Tag: "vpn-tc-ext", Enabled: true,
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: extData,
	}
	if err := st.CreateVPN(ctx, extVPN); err != nil {
		t.Fatal(err)
	}
	acmeVPN := &domain.VPN{
		Name: "tc-acme", Protocol: "tuic", Tag: "vpn-tc-acme", Enabled: true,
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8444},
		ProtocolData: acmeData,
	}
	if err := st.CreateVPN(ctx, acmeVPN); err != nil {
		t.Fatal(err)
	}
	for _, spec := range []struct {
		vpnID int64
		name  string
		uuid  string
		pass  string
	}{
		{extVPN.ID, "phone", "550e8400-e29b-41d4-a716-446655440000", "secret1"},
		{acmeVPN.ID, "tablet", "660e8400-e29b-41d4-a716-446655440001", "secret2"},
	} {
		client := &domain.Client{
			VPNID: spec.vpnID, Name: spec.name,
			Username: spec.uuid, Password: spec.pass, Enabled: true,
		}
		if err := st.CreateClient(ctx, client); err != nil {
			t.Fatal(err)
		}
	}
	r := render.NewRenderer(st, runtime.NewProtocolRegistry())
	raw, err := r.Render(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "sing-box", "check", "-c", cfgPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check: %v: %s", err, out)
	}
}

// TestSingBoxCheckTUICInbound validates rendered TUIC config with sing-box check.
func TestSingBoxCheckTUICInbound(t *testing.T) {
	if _, err := exec.LookPath("sing-box"); err != nil {
		t.Skip("sing-box not installed")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	cfgPath := filepath.Join(dir, "sing-box.json")
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	if err := certs.GenerateSelfSigned("example.com", certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	protocolData, err := tuic.MarshalProtocolData(tuic.ProtocolData{
		CertPath: certPath, KeyPath: keyPath, ServerName: "example.com",
		ALPN: []string{"h3"}, CongestionControl: "bbr",
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	vpn := &domain.VPN{
		Name: "tc", Protocol: "tuic", Tag: "vpn-tc", Enabled: true,
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: protocolData,
	}
	if err := st.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	client := &domain.Client{
		VPNID: vpn.ID, Name: "phone",
		Username: "550e8400-e29b-41d4-a716-446655440000",
		Password: "secret", Enabled: true,
	}
	if err := st.CreateClient(ctx, client); err != nil {
		t.Fatal(err)
	}
	r := render.NewRenderer(st, runtime.NewProtocolRegistry())
	raw, err := r.Render(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "sing-box", "check", "-c", cfgPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check: %v: %s", err, out)
	}
}

// TestSingBoxCheckWireguardEndpoint validates rendered WireGuard endpoint config with sing-box check.
func TestSingBoxCheckWireguardEndpoint(t *testing.T) {
	if _, err := exec.LookPath("sing-box"); err != nil {
		t.Skip("sing-box not installed")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	cfgPath := filepath.Join(dir, "sing-box.json")
	serverPair, err := wireguard.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	clientPair, err := wireguard.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	protocolData, err := wireguard.MarshalProtocolData(wireguard.ProtocolData{
		PrivateKey: serverPair.PrivateKey,
		PublicKey:  serverPair.PublicKey,
		Address:    []string{"10.8.0.1/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	vpn := &domain.VPN{
		Name: "wg", Protocol: "wireguard", Tag: "vpn-wg", Enabled: true,
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 51820},
		ProtocolData: protocolData,
	}
	if err := st.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	client := &domain.Client{
		VPNID: vpn.ID, Name: "phone",
		Username: clientPair.PublicKey, Password: clientPair.PrivateKey, Enabled: true,
	}
	if err := st.CreateClient(ctx, client); err != nil {
		t.Fatal(err)
	}
	r := render.NewRenderer(st, runtime.NewProtocolRegistry())
	raw, err := r.Render(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "sing-box", "check", "-c", cfgPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check: %v: %s", err, out)
	}
}

// TestSingBoxCheckWireguardAllDialOptions validates WireGuard endpoint dial fields with sing-box check.
// Skips detour, netns, inet6 bind, and network_strategy — they require extra outbounds/namespaces
// or conflict with bind/tcp_fast_open fields in sing-box.
func TestSingBoxCheckWireguardAllDialOptions(t *testing.T) {
	if _, err := exec.LookPath("sing-box"); err != nil {
		t.Skip("sing-box not installed")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	cfgPath := filepath.Join(dir, "sing-box.json")
	serverPair, err := wireguard.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	clientPair, err := wireguard.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	protocolData, err := wireguard.MarshalProtocolData(wireguard.ProtocolData{
		PrivateKey:           serverPair.PrivateKey,
		PublicKey:            serverPair.PublicKey,
		Address:              []string{"10.8.0.1/24"},
		BindInterface:        "eth0",
		RoutingMark:          "0x1",
		Inet4BindAddress:     "0.0.0.0",
		BindAddressNoPort:    true,
		TCPFastOpen:          true,
		TCPMultiPath:         true,
		DisableTCPKeepAlive:  true,
		TCPKeepAlive:         "30s",
		TCPKeepAliveInterval: "15s",
		UDPFragment:          true,
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	vpn := &domain.VPN{
		Name: "wg-dial", Protocol: "wireguard", Tag: "vpn-wg-dial", Enabled: true,
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 51820},
		ProtocolData: protocolData,
	}
	if err := st.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	client := &domain.Client{
		VPNID: vpn.ID, Name: "phone",
		Username: clientPair.PublicKey, Password: clientPair.PrivateKey, Enabled: true,
	}
	if err := st.CreateClient(ctx, client); err != nil {
		t.Fatal(err)
	}
	r := render.NewRenderer(st, runtime.NewProtocolRegistry())
	raw, err := r.Render(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "sing-box", "check", "-c", cfgPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check: %v: %s", err, out)
	}
}

// TestSingBoxCheckWireguardNetworkStrategy validates network_strategy dial fields without bind/tcp_fast_open.
func TestSingBoxCheckWireguardNetworkStrategy(t *testing.T) {
	if _, err := exec.LookPath("sing-box"); err != nil {
		t.Skip("sing-box not installed")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	cfgPath := filepath.Join(dir, "sing-box.json")
	serverPair, err := wireguard.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	clientPair, err := wireguard.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	protocolData, err := wireguard.MarshalProtocolData(wireguard.ProtocolData{
		PrivateKey:          serverPair.PrivateKey,
		PublicKey:           serverPair.PublicKey,
		Address:             []string{"10.8.0.1/24"},
		NetworkStrategy:     "default",
		NetworkType:         []string{"wifi"},
		FallbackNetworkType: []string{"cellular"},
		FallbackDelay:       "300ms",
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	vpn := &domain.VPN{
		Name: "wg-net", Protocol: "wireguard", Tag: "vpn-wg-net", Enabled: true,
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 51820},
		ProtocolData: protocolData,
	}
	if err := st.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	client := &domain.Client{
		VPNID: vpn.ID, Name: "phone",
		Username: clientPair.PublicKey, Password: clientPair.PrivateKey, Enabled: true,
	}
	if err := st.CreateClient(ctx, client); err != nil {
		t.Fatal(err)
	}
	r := render.NewRenderer(st, runtime.NewProtocolRegistry())
	raw, err := r.Render(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "sing-box", "check", "-c", cfgPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check: %v: %s", err, out)
	}
}
