package service_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ivan-khludov/obscura/internal/config"
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/firewall"
	"github.com/ivan-khludov/obscura/internal/manifest"
	"github.com/ivan-khludov/obscura/internal/protocol/httpproxy"
	"github.com/ivan-khludov/obscura/internal/protocol/hysteria2"
	"github.com/ivan-khludov/obscura/internal/protocol/shadowsocks"
	"github.com/ivan-khludov/obscura/internal/protocol/trojan"
	"github.com/ivan-khludov/obscura/internal/protocol/tuic"
	"github.com/ivan-khludov/obscura/internal/protocol/vless"
	"github.com/ivan-khludov/obscura/internal/protocol/vmess"
	"github.com/ivan-khludov/obscura/internal/protocol/wireguard"
	"github.com/ivan-khludov/obscura/internal/runtime"
	"github.com/ivan-khludov/obscura/internal/service"
	"github.com/ivan-khludov/obscura/internal/singboxcheck"
	"github.com/ivan-khludov/obscura/internal/sysctl"
	"github.com/ivan-khludov/obscura/internal/systemd"
)

func TestCreateVPNAutoAddsDefaultClient(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	result, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Client == nil || result.Client.Name != "default" {
		t.Fatalf("expected default client, got %#v", result.Client)
	}
	if result.URI == "" {
		t.Fatal("expected client uri")
	}
	clients, err := svc.ListClients(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 1 || clients[0].Name != "default" {
		t.Fatalf("unexpected clients: %#v", clients)
	}
}

// TestCreateVPNClientHostURI verifies per-VPN client host appears in share links.
func TestCreateVPNClientHostURI(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	result, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "hy", Protocol: "hysteria2", Enabled: true,
		ClientHost: "culhackervpn.duckdns.org",
		Listen:     domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 20783},
		Hysteria2:  service.Hysteria2CreateOptions{ServerName: "culhackervpn.duckdns.org"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.VPN.ClientHost != "culhackervpn.duckdns.org" {
		t.Fatalf("client_host = %q", result.VPN.ClientHost)
	}
	if !strings.Contains(result.URI, "culhackervpn.duckdns.org:20783") {
		t.Fatalf("unexpected uri: %q", result.URI)
	}
	cleared := ""
	if _, err := svc.UpdateVPN(ctx, "hy", service.UpdateVPNInput{ClientHost: &cleared}, false); err != nil {
		t.Fatal(err)
	}
	uri, err := svc.ClientURI(ctx, "hy", result.Client.Name)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(uri, "@culhackervpn.duckdns.org:") {
		t.Fatalf("expected auto host after clear, got %q", uri)
	}
}

// TestCreateVPNAutoApplies verifies enabled VPN creation reloads sing-box.
func TestCreateVPNAutoApplies(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir:      dir,
		DBPath:       filepath.Join(dir, "state.db"),
		ConfigPath:   filepath.Join(dir, "sing-box.json"),
		ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode:      true,
		ServerHost:   "127.0.0.1",
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	reload := &reloadRecorder{}
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, reload)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080},
	}); err != nil {
		t.Fatal(err)
	}
	if !reload.called {
		t.Fatal("expected apply to reload sing-box")
	}
	if _, err := os.Stat(app.ConfigPath); err != nil {
		t.Fatalf("expected config written: %v", err)
	}
}

// TestCreateVPNAndClientApply verifies VPN/client creation and dry-run apply.
func TestDeleteVPNWithClient(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "my", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1083},
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteVPN(ctx, "my"); err != nil {
		t.Fatalf("delete vpn with client: %v", err)
	}
	vpns, err := svc.ListVPNs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(vpns) != 0 {
		t.Fatalf("expected 0 vpns after delete, got %d", len(vpns))
	}
}

// TestDeleteVPNRemovesFirewallRule verifies VPN delete removes firewall tracking.
func TestDeleteVPNRemovesFirewallRule(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir:      dir,
		DBPath:       filepath.Join(dir, "state.db"),
		ConfigPath:   filepath.Join(dir, "sing-box.json"),
		ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode:      true,
		ServerHost:   "127.0.0.1",
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	fw := &trackingFirewall{}
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, fw, singboxcheck.NopChecker{}, systemd.NopManager{})
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1082},
	}); err != nil {
		t.Fatal(err)
	}
	plan := svc.UninstallPlan()
	if len(plan.RemoveFirewall) != 1 || plan.RemoveFirewall[0] != "1082/tcp" {
		t.Fatalf("unexpected firewall rules: %#v", plan.RemoveFirewall)
	}
	if err := svc.DeleteVPN(ctx, "main"); err != nil {
		t.Fatal(err)
	}
	if len(fw.deleted) != 1 || fw.deleted[0] != "1082/tcp" {
		t.Fatalf("expected firewall delete, got %#v", fw.deleted)
	}
	// The SSH allow rule survives VPN deletion in ufw, and the uninstall plan
	// never lists it, so the controlling session is never dropped.
	plan = svc.UninstallPlan()
	if len(plan.RemoveFirewall) != 0 {
		t.Fatalf("expected no firewall rules in plan (SSH filtered), got %#v", plan.RemoveFirewall)
	}
}

// TestRestoreBackupCheckAndReload verifies restore validates config and reloads sing-box.
func TestCreateVPN_RollbackOnApplyFailure(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir:      dir,
		DBPath:       filepath.Join(dir, "state.db"),
		ConfigPath:   filepath.Join(dir, "sing-box.json"),
		ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode:      true,
		ServerHost:   "127.0.0.1",
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, failChecker{}, systemd.NopManager{})
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1092},
	}); err == nil {
		t.Fatal("expected create vpn to fail on apply")
	}
	vpns, err := svc.ListVPNs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(vpns) != 0 {
		t.Fatalf("expected vpn rolled back, got %#v", vpns)
	}
}

// TestUpdateVPN_PortChangeReapplies verifies edit with apply reloads sing-box.
func TestUpdateVPN_PortChangeReapplies(t *testing.T) {
	reloader := &reloadRecorder{}
	dir := t.TempDir()
	app := &config.App{
		DataDir:      dir,
		DBPath:       filepath.Join(dir, "state.db"),
		ConfigPath:   filepath.Join(dir, "sing-box.json"),
		ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode:      true,
		ServerHost:   "127.0.0.1",
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, reloader)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1093},
	}); err != nil {
		t.Fatal(err)
	}
	reloader.called = false
	newPort := 1193
	if _, err := svc.UpdateVPN(ctx, "main", service.UpdateVPNInput{
		Listen: &domain.ListenOptions{Listen: "0.0.0.0", ListenPort: newPort},
	}, true); err != nil {
		t.Fatal(err)
	}
	if !reloader.called {
		t.Fatal("expected reload after update")
	}
	vpn, err := svc.GetVPN(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	if vpn.Listen.ListenPort != newPort {
		t.Fatalf("expected port %d, got %d", newPort, vpn.Listen.ListenPort)
	}
}

// TestValidateUniquePort rejects duplicate listen ports.
func TestCreateVPNHTTP(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	result, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "web", Protocol: "http", Enabled: true,
		Listen:            domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8080},
		InitialClientName: "phone",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.VPN.Protocol != "http" {
		t.Fatalf("expected http protocol, got %q", result.VPN.Protocol)
	}
	if !strings.HasPrefix(result.URI, "http://") {
		t.Fatalf("expected http uri, got %q", result.URI)
	}
}

// TestCreateVPNHTTPTLS verifies TLS cert generation and protocol data.
func TestCreateVPNHTTPTLS(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	result, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "secure", Protocol: "http", Enabled: false,
		Listen:            domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8443},
		InitialClientName: "laptop", HTTPTLS: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(result.URI, "https://") {
		t.Fatalf("expected https uri, got %q", result.URI)
	}
	data, err := httpproxy.ParseProtocolData(result.VPN.ProtocolData)
	if err != nil {
		t.Fatal(err)
	}
	if !data.TLS || data.CertPath == "" || data.KeyPath == "" {
		t.Fatalf("unexpected protocol data: %#v", data)
	}
	if _, err := os.Stat(data.CertPath); err != nil {
		t.Fatalf("cert missing: %v", err)
	}
	if _, err := os.Stat(data.KeyPath); err != nil {
		t.Fatalf("key missing: %v", err)
	}
}

// TestUpdateVPN_FirewallPortSync verifies port change updates firewall rules.
func TestUpdateVPN_FirewallPortSync(t *testing.T) {
	fw := &trackingFirewall{}
	dir := t.TempDir()
	app := &config.App{
		DataDir:      dir,
		DBPath:       filepath.Join(dir, "state.db"),
		ConfigPath:   filepath.Join(dir, "sing-box.json"),
		ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode:      true,
		ServerHost:   "127.0.0.1",
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, fw, singboxcheck.NopChecker{}, systemd.NopManager{})
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: true,
		Listen:            domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1095},
		InitialClientName: "phone",
	}); err != nil {
		t.Fatal(err)
	}
	fw.deleted = nil
	fw.allowed = nil
	newPort := 1195
	if _, err := svc.UpdateVPN(ctx, "main", service.UpdateVPNInput{
		Listen: &domain.ListenOptions{Listen: "0.0.0.0", ListenPort: newPort},
	}, false); err != nil {
		t.Fatal(err)
	}
	if len(fw.deleted) != 1 || fw.deleted[0] != "1095/tcp" {
		t.Fatalf("expected old rule deleted, got %#v", fw.deleted)
	}
	// SSH is re-asserted before the ufw reload, then the new VPN port is allowed.
	if len(fw.allowed) != 2 || fw.allowed[0] != "22/tcp" || fw.allowed[1] != "1195/tcp" {
		t.Fatalf("expected SSH and new rule allowed, got %#v", fw.allowed)
	}
}

// TestUpdateVPN_HTTPTLSToggle verifies TLS can be enabled and disabled on http VPN.
func TestUpdateVPN_HTTPTLSToggle(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "web", Protocol: "http", Enabled: true,
		Listen:            domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8080},
		InitialClientName: "phone",
	}); err != nil {
		t.Fatal(err)
	}
	tlsOn := true
	vpn, err := svc.UpdateVPN(ctx, "web", service.UpdateVPNInput{HTTPTLS: &tlsOn}, false)
	if err != nil {
		t.Fatal(err)
	}
	data, err := httpproxy.ParseProtocolData(vpn.ProtocolData)
	if err != nil || !data.TLS {
		t.Fatalf("expected tls enabled, got %#v err=%v", data, err)
	}
	tlsOff := false
	vpn, err = svc.UpdateVPN(ctx, "web", service.UpdateVPNInput{HTTPTLS: &tlsOff}, false)
	if err != nil {
		t.Fatal(err)
	}
	data, err = httpproxy.ParseProtocolData(vpn.ProtocolData)
	if err != nil || data.TLS {
		t.Fatalf("expected tls disabled, got %#v err=%v", data, err)
	}
}

// TestUpdateClient_Rename verifies client rename.
func TestCreateVPNShadowsocks(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	result, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "ss", Protocol: "shadowsocks", Enabled: true,
		Listen:            domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8388},
		InitialClientName: "phone",
		SSMethod:          shadowsocks.DefaultMethod,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.VPN.Protocol != "shadowsocks" {
		t.Fatalf("expected shadowsocks protocol, got %q", result.VPN.Protocol)
	}
	data, err := shadowsocks.ParseProtocolData(result.VPN.ProtocolData)
	if err != nil || data.Method != shadowsocks.DefaultMethod || data.ServerPassword == "" {
		t.Fatalf("unexpected protocol data: %#v err=%v", data, err)
	}
	if !strings.HasPrefix(result.URI, "ss://") {
		t.Fatalf("expected ss uri, got %q", result.URI)
	}
	if err := shadowsocks.ValidateKey(data.Method, result.Client.Password); err != nil {
		t.Fatalf("invalid client key: %v", err)
	}
}

// TestCreateVPNShadowsocksMultiplex verifies multiplex settings are stored in protocol data.
func TestCreateVPNShadowsocksMultiplex(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	result, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "ss", Protocol: "shadowsocks", Enabled: true,
		Listen:            domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8388},
		InitialClientName: "phone",
		SSMethod:          shadowsocks.DefaultMethod,
		SSMultiplex:       true, SSMultiplexPadding: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := shadowsocks.ParseProtocolData(result.VPN.ProtocolData)
	if err != nil || !data.Multiplex || !data.MultiplexPadding {
		t.Fatalf("unexpected protocol data: %#v err=%v", data, err)
	}
}

// TestCreateVPNShadowsocksShadowTLS verifies ShadowTLS settings are stored in protocol data.
func TestCreateVPNShadowsocksShadowTLS(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	result, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "ss", Protocol: "shadowsocks", Enabled: true,
		Listen:            domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		InitialClientName: "phone",
		SSMethod:          shadowsocks.DefaultMethod,
		SSShadowTLS:       true, SSShadowTLSHandshake: "www.bing.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := shadowsocks.ParseProtocolData(result.VPN.ProtocolData)
	if err != nil || !data.ShadowTLS || data.ShadowTLSPassword == "" || data.ShadowTLSHandshake != "www.bing.com" {
		t.Fatalf("unexpected protocol data: %#v err=%v", data, err)
	}
}

// TestCreateVPNTrojan verifies Trojan VPN creation stores TLS protocol data and trojan URI.
func TestCreateVPNTrojan(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	result, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "tr", Protocol: "trojan", Enabled: false,
		Listen:            domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		InitialClientName: "phone",
		Trojan: service.TrojanCreateOptions{
			ServerName: "example.com",
			Multiplex:  true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := trojan.ParseProtocolData(result.VPN.ProtocolData)
	if err != nil {
		t.Fatal(err)
	}
	if data.CertPath == "" || data.KeyPath == "" || data.ServerName != "example.com" || !data.Multiplex {
		t.Fatalf("unexpected protocol data: %#v", data)
	}
	if _, err := os.Stat(data.CertPath); err != nil {
		t.Fatalf("cert missing: %v", err)
	}
	if !strings.HasPrefix(result.URI, "trojan://") {
		t.Fatalf("expected trojan uri, got %q", result.URI)
	}
}

// TestCreateVPNWireguard verifies WireGuard VPN creation stores protocol data and wireguard URI.
func TestCreateVPNWireguard(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	result, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "wg", Protocol: "wireguard", Enabled: false,
		Listen:            domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 51820},
		InitialClientName: "phone",
		Wireguard: service.WireguardCreateOptions{
			Address: []string{"10.8.0.1/24"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := wireguard.ParseProtocolData(result.VPN.ProtocolData)
	if err != nil {
		t.Fatal(err)
	}
	if data.PrivateKey == "" || data.PublicKey == "" || len(data.Address) != 1 {
		t.Fatalf("unexpected protocol data: %#v", data)
	}
	if result.Client == nil || result.Client.Username == "" || result.Client.Password == "" {
		t.Fatalf("expected wireguard client keys, got %#v", result.Client)
	}
	if !strings.HasPrefix(result.URI, "wireguard://") {
		t.Fatalf("expected wireguard uri, got %q", result.URI)
	}
	qr, err := svc.ClientQRContent(ctx, "wg", "phone")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(qr, "[Interface]") {
		t.Fatalf("expected conf qr content, got %q", qr[:min(20, len(qr))])
	}
	if qr == result.URI {
		t.Fatal("expected QR content to differ from URI")
	}
}

// TestCreateVPNVmess verifies VMess VPN creation stores TLS protocol data, UUID client creds, and vmess URI.
func TestCreateVPNVmess(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	result, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "vm", Protocol: "vmess", Enabled: false,
		Listen:            domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		InitialClientName: "phone",
		VMess: service.VMessCreateOptions{
			ServerName: "example.com",
			Multiplex:  true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := vmess.ParseProtocolData(result.VPN.ProtocolData)
	if err != nil {
		t.Fatal(err)
	}
	if data.CertPath == "" || data.KeyPath == "" || data.ServerName != "example.com" || !data.Multiplex {
		t.Fatalf("unexpected protocol data: %#v", data)
	}
	if _, err := os.Stat(data.CertPath); err != nil {
		t.Fatalf("cert missing: %v", err)
	}
	if result.Client == nil || result.Client.Password == "" {
		t.Fatalf("expected vmess client uuid, got %#v", result.Client)
	}
	if _, err := uuid.Parse(result.Client.Password); err != nil {
		t.Fatalf("expected valid uuid password, got %q: %v", result.Client.Password, err)
	}
	if !strings.HasPrefix(result.URI, "vmess://") {
		t.Fatalf("expected vmess uri, got %q", result.URI)
	}
}

// TestCreateVPNVless verifies VLESS VPN creation stores TLS protocol data, UUID client creds, and vless URI.
func TestCreateVPNVless(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	result, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "vl", Protocol: "vless", Enabled: false,
		Listen:            domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		InitialClientName: "phone",
		VLESS: service.VLESSCreateOptions{
			ServerName: "example.com",
			Multiplex:  true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := vless.ParseProtocolData(result.VPN.ProtocolData)
	if err != nil {
		t.Fatal(err)
	}
	if data.CertPath == "" || data.KeyPath == "" || data.ServerName != "example.com" || !data.Multiplex {
		t.Fatalf("unexpected protocol data: %#v", data)
	}
	if _, err := uuid.Parse(result.Client.Password); err != nil {
		t.Fatalf("expected valid uuid password, got %q: %v", result.Client.Password, err)
	}
	if !strings.HasPrefix(result.URI, "vless://") {
		t.Fatalf("expected vless uri, got %q", result.URI)
	}
}

// TestCreateVPNHysteria2 verifies Hysteria2 VPN creation stores TLS protocol data, password client creds, and hysteria2 URI.
func TestCreateVPNHysteria2(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	result, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "hy", Protocol: "hysteria2", Enabled: false,
		Listen:            domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		InitialClientName: "phone",
		Hysteria2: service.Hysteria2CreateOptions{
			ServerName:   "example.com",
			ObfsPassword: "obfs-secret",
			UpMbps:       100,
			DownMbps:     100,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := hysteria2.ParseProtocolData(result.VPN.ProtocolData)
	if err != nil {
		t.Fatal(err)
	}
	if data.CertPath == "" || data.KeyPath == "" || data.ServerName != "example.com" || data.ObfsPassword != "obfs-secret" {
		t.Fatalf("unexpected protocol data: %#v", data)
	}
	if result.Client.Password == "" {
		t.Fatal("expected password client creds")
	}
	if !strings.HasPrefix(result.URI, "hysteria2://") {
		t.Fatalf("expected hysteria2 uri, got %q", result.URI)
	}
}

// TestCreateVPNTUIC verifies TUIC VPN creation stores TLS protocol data, UUID username, password, and tuic URI.
func TestCreateVPNTUIC(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	result, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "tc", Protocol: "tuic", Enabled: false,
		Listen:            domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		InitialClientName: "phone",
		TUIC: service.TUICCreateOptions{
			ServerName:        "example.com",
			CongestionControl: "bbr",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := tuic.ParseProtocolData(result.VPN.ProtocolData)
	if err != nil {
		t.Fatal(err)
	}
	if data.CertPath == "" || data.KeyPath == "" || data.ServerName != "example.com" || data.CongestionControl != "bbr" {
		t.Fatalf("unexpected protocol data: %#v", data)
	}
	if result.Client.Username == "" {
		t.Fatal("expected uuid username")
	}
	if _, err := uuid.Parse(result.Client.Username); err != nil {
		t.Fatalf("expected valid uuid username, got %q: %v", result.Client.Username, err)
	}
	if result.Client.Password == "" {
		t.Fatal("expected password client creds")
	}
	if !strings.HasPrefix(result.URI, "tuic://") {
		t.Fatalf("expected tuic uri, got %q", result.URI)
	}
}

// TestBootstrapWithFallbackStubDev copies fallback assets in dev mode.
func TestCreateVPNOnSSHPort(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir:      dir,
		DBPath:       filepath.Join(dir, "state.db"),
		ConfigPath:   filepath.Join(dir, "sing-box.json"),
		ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode:      true,
		ServerHost:   "127.0.0.1",
	}
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	man.SetSSHPort(22)
	if err := man.Save(); err != nil {
		t.Fatal(err)
	}
	st := mustOpenStore(t, app.DBPath)
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	ctx := context.Background()
	_, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 22},
	})
	if err == nil {
		t.Fatal("expected error creating VPN on SSH port")
	}
	if !strings.Contains(err.Error(), "reserved for SSH") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListVPNsSorted(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	for _, spec := range []struct {
		name string
		port int
	}{
		{"beta", 12002},
		{"alpha", 12001},
	} {
		if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
			Name: spec.name, Protocol: "socks5", Enabled: false,
			Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: spec.port},
		}); err != nil {
			t.Fatal(err)
		}
	}
	vpns, err := svc.ListVPNs(ctx)
	if err != nil || len(vpns) != 2 {
		t.Fatalf("list: %v len=%d", err, len(vpns))
	}
	if vpns[0].Name != "alpha" || vpns[1].Name != "beta" {
		t.Fatalf("sort order: %#v", vpns)
	}
	got, err := svc.GetVPN(ctx, "alpha")
	if err != nil || got.Name != "alpha" {
		t.Fatalf("get: %v %#v", err, got)
	}
}

func TestUpdateVPNRenameAndDisable(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{ListenPort: 12003},
	}); err != nil {
		t.Fatal(err)
	}
	newName := "renamed"
	enabled := false
	if _, err := svc.UpdateVPN(ctx, "main", service.UpdateVPNInput{Name: &newName, Enabled: &enabled}, false); err != nil {
		t.Fatal(err)
	}
}

func TestCreateVPNEmptyName(t *testing.T) {
	svc, _ := newTestService(t)
	_, err := svc.CreateVPN(context.Background(), service.CreateVPNInput{
		Protocol: "socks5", Listen: domain.ListenOptions{ListenPort: 12004},
	})
	if err == nil {
		t.Fatal("expected name required")
	}
}

func TestUpdateVPNFirewallAllowError(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: true, ServerHost: "127.0.0.1",
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, errorFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{ListenPort: 11003},
	}); err != nil {
		t.Fatal(err)
	}
	newPort := 11004
	if _, err := svc.UpdateVPN(ctx, "main", service.UpdateVPNInput{
		Listen: &domain.ListenOptions{Listen: "0.0.0.0", ListenPort: newPort},
	}, false); err == nil {
		t.Fatal("expected firewall error")
	}
}

func TestCreateVPNNoInitialClient(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: true, ServerHost: "127.0.0.1",
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	reg := customRegistry(t, noInitialClientProtocol{})
	svc := service.NewService(app, st, reg, man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	ctx := context.Background()
	result, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "nc", Protocol: "noclient", Enabled: true,
		Listen: domain.ListenOptions{ListenPort: 12010},
	})
	if err != nil || result.Client != nil {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestCreateVPNInitialClientFail(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: true,
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	reg := customRegistry(t, uriFailProtocol{})
	svc := service.NewService(app, st, reg, man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "uri", Protocol: "urifail", Enabled: false,
		Listen: domain.ListenOptions{ListenPort: 12011},
	}); err == nil {
		t.Fatal("expected initial client error")
	}
}

func TestCreateVPNUnknownProtocol(t *testing.T) {
	svc, _ := newTestService(t)
	if _, err := svc.CreateVPN(context.Background(), service.CreateVPNInput{
		Name: "x", Protocol: "unknown", Listen: domain.ListenOptions{ListenPort: 12012},
	}); err == nil {
		t.Fatal("expected unknown protocol")
	}
}

func TestCreateVPNInvalidClientHost(t *testing.T) {
	svc, _ := newTestService(t)
	if _, err := svc.CreateVPN(context.Background(), service.CreateVPNInput{
		Name: "x", Protocol: "socks5", ClientHost: "not a host!!!",
		Listen: domain.ListenOptions{ListenPort: 12013},
	}); err == nil {
		t.Fatal("expected client host error")
	}
}

func TestDeleteVPNNotFound(t *testing.T) {
	svc, _ := newTestService(t)
	if err := svc.DeleteVPN(context.Background(), "missing"); err == nil {
		t.Fatal("expected error")
	}
}

func TestUpdateVPNErrors(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	blank := "  "
	if _, err := svc.UpdateVPN(ctx, "missing", service.UpdateVPNInput{Name: &blank}, false); err == nil {
		t.Fatal("expected missing vpn")
	}
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: false,
		Listen: domain.ListenOptions{ListenPort: 12014},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateVPN(ctx, "main", service.UpdateVPNInput{Name: &blank}, false); err == nil {
		t.Fatal("expected empty name")
	}
	tlsOn := true
	if _, err := svc.UpdateVPN(ctx, "main", service.UpdateVPNInput{HTTPTLS: &tlsOn}, false); err == nil {
		t.Fatal("expected tls protocol error")
	}
}

func TestUpdateVPNApplyError(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: true,
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, applyFailReload{})
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: false,
		Listen: domain.ListenOptions{ListenPort: 12015},
	}); err != nil {
		t.Fatal(err)
	}
	enabled := true
	if _, err := svc.UpdateVPN(ctx, "main", service.UpdateVPNInput{Enabled: &enabled}, true); err == nil {
		t.Fatal("expected apply error")
	}
}

func TestListVPNsClosedStore(t *testing.T) {
	svc := closedStoreService(t)
	if _, err := svc.ListVPNs(context.Background()); err == nil {
		t.Fatal("expected store error")
	}
}

func TestDeleteVPNApplyError(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: true,
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, applyFailReload{})
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: false,
		Listen: domain.ListenOptions{ListenPort: 12020},
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteVPN(ctx, "main"); err == nil {
		t.Fatal("expected apply error")
	}
}

func TestCreateVPNNoInitialClientApplyFail(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: true,
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	reg := customRegistry(t, noInitialClientProtocol{})
	svc := service.NewService(app, st, reg, man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, applyFailReload{})
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "nc", Protocol: "noclient", Enabled: true,
		Listen: domain.ListenOptions{ListenPort: 12021},
	}); err == nil {
		t.Fatal("expected apply error")
	}
}

func TestUpdateVPNParseHTTPTLSError(t *testing.T) {
	svc, st := newTestService(t)
	ctx := context.Background()
	vpn := &domain.VPN{
		Name: "web", Protocol: "http", Tag: "vpn-web", Enabled: true,
		Listen: domain.ListenOptions{ListenPort: 12022}, ProtocolData: []byte("bad"),
	}
	if err := st.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	tlsOn := true
	if _, err := svc.UpdateVPN(ctx, "web", service.UpdateVPNInput{HTTPTLS: &tlsOn}, false); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestUpdateVPNListClientsError(t *testing.T) {
	svc, st := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: false,
		Listen: domain.ListenOptions{ListenPort: 12023},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	enabled := true
	if _, err := svc.UpdateVPN(ctx, "main", service.UpdateVPNInput{Enabled: &enabled}, false); err == nil {
		t.Fatal("expected store error")
	}
}

func TestVPNStoreFaults(t *testing.T) {
	ctx := context.Background()
	storeErr := fmt.Errorf("store failed")

	t.Run("CreateVPNStoreError", func(t *testing.T) {
		svc, st := newTestService(t)
		fs := wrapFaultStore(st)
		fs.createVPNErr = storeErr
		svc.SetStoreForTest(fs)
		if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{Name: "x", Protocol: "socks5", Enabled: false, Listen: domain.ListenOptions{ListenPort: 12030}}); err == nil {
			t.Fatal("expected create error")
		}
	})

	t.Run("UpdateVPNStoreErrors", func(t *testing.T) {
		svc, st := newTestService(t)
		if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{Name: "main", Protocol: "socks5", Enabled: false, Listen: domain.ListenOptions{ListenPort: 12031}}); err != nil {
			t.Fatal(err)
		}
		fs := wrapFaultStore(st)
		fs.listClientsErr = storeErr
		svc.SetStoreForTest(fs)
		if _, err := svc.UpdateVPN(ctx, "main", service.UpdateVPNInput{}, false); err == nil {
			t.Fatal("expected list clients error")
		}
		fs.listClientsErr = nil
		fs.updateVPNErr = storeErr
		if _, err := svc.UpdateVPN(ctx, "main", service.UpdateVPNInput{}, false); err == nil {
			t.Fatal("expected update error")
		}
	})

	t.Run("DeleteVPNStoreError", func(t *testing.T) {
		svc, st := newTestService(t)
		if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{Name: "main", Protocol: "socks5", Enabled: false, Listen: domain.ListenOptions{ListenPort: 12032}}); err != nil {
			t.Fatal(err)
		}
		fs := wrapFaultStore(st)
		fs.deleteVPNErr = storeErr
		svc.SetStoreForTest(fs)
		if err := svc.DeleteVPN(ctx, "main"); err == nil {
			t.Fatal("expected delete error")
		}
	})

	t.Run("ListVPNsSortByName", func(t *testing.T) {
		svc, _ := newTestService(t)
		port := 12033
		for _, name := range []string{"bbb", "aaa"} {
			if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{Name: name, Protocol: "socks5", Enabled: false, Listen: domain.ListenOptions{ListenPort: port}}); err != nil {
				t.Fatal(err)
			}
		}
		vpns, err := svc.ListVPNs(ctx)
		if err != nil || len(vpns) != 2 || vpns[0].Name != "aaa" {
			t.Fatalf("vpns=%#v err=%v", vpns, err)
		}
	})

	t.Run("CreateVPNDefaultListen", func(t *testing.T) {
		svc, _ := newTestService(t)
		res, err := svc.CreateVPN(ctx, service.CreateVPNInput{Name: "dl", Protocol: "socks5", Enabled: false})
		if err != nil {
			t.Fatal(err)
		}
		if res.VPN.Listen.Listen == "" || res.VPN.Listen.ListenPort == 0 {
			t.Fatalf("listen=%#v", res.VPN.Listen)
		}
	})

	t.Run("DeleteVPNUnknownProtocol", func(t *testing.T) {
		svc, st := newTestService(t)
		vpn := &domain.VPN{Name: "bad", Protocol: "unknown", Tag: "vpn-bad", Enabled: false, Listen: domain.ListenOptions{ListenPort: 12035}, ProtocolData: []byte("{}")}
		if err := st.CreateVPN(ctx, vpn); err != nil {
			t.Fatal(err)
		}
		if err := svc.DeleteVPN(ctx, "bad"); err == nil {
			t.Fatal("expected protocol error")
		}
	})

	t.Run("UpdateVPNEnableHTTPTLSError", func(t *testing.T) {
		svc, st := newTestService(t)
		vpn := &domain.VPN{Name: "web", Protocol: "http", Tag: "vpn-web", Enabled: true, Listen: domain.ListenOptions{ListenPort: 12036}, ProtocolData: []byte("{}")}
		if err := st.CreateVPN(ctx, vpn); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(svc.DataDir(), 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(svc.DataDir(), 0o755) })
		tlsOn := true
		if _, err := svc.UpdateVPN(ctx, "web", service.UpdateVPNInput{HTTPTLS: &tlsOn}, false); err == nil {
			t.Fatal("expected tls enable error")
		}
	})

	t.Run("UpdateVPNValidateVPNError", func(t *testing.T) {
		dir := t.TempDir()
		app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "m.json"), DevMode: true}
		st := mustOpenStore(t, app.DBPath)
		man := manifest.NewManager(app.ManifestPath)
		_ = man.Load()
		reg := customRegistry(t, validateVPNFailProtocol{})
		svc := service.NewService(app, st, reg, man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
		vpn := &domain.VPN{Name: "vf", Protocol: "valfail", Tag: "vpn-vf", Enabled: false, Listen: domain.ListenOptions{ListenPort: 12040}, ProtocolData: []byte("{}")}
		if err := st.CreateVPN(ctx, vpn); err != nil {
			t.Fatal(err)
		}
		if err := st.CreateClient(ctx, &domain.Client{VPNID: vpn.ID, Name: "c", Username: "u", Password: "p", Enabled: true}); err != nil {
			t.Fatal(err)
		}
		enabled := true
		if _, err := svc.UpdateVPN(ctx, "vf", service.UpdateVPNInput{Enabled: &enabled}, false); err == nil {
			t.Fatal("expected validate error")
		}
	})

	t.Run("CreateVPNStoreCreateError", func(t *testing.T) {
		svc, st := newTestService(t)
		fs := wrapFaultStore(st)
		fs.createVPNErr = storeErr
		svc.SetStoreForTest(fs)
		if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{Name: "x", Protocol: "socks5", Enabled: false, Listen: domain.ListenOptions{ListenPort: 12050}}); err == nil {
			t.Fatal("expected create error")
		}
	})

	t.Run("SyncFirewallPortUnknownProtocol", func(t *testing.T) {
		dir := t.TempDir()
		app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "m.json"), DevMode: true}
		st := mustOpenStore(t, app.DBPath)
		man := manifest.NewManager(app.ManifestPath)
		_ = man.Load()
		svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, &trackingFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
		vpn := &domain.VPN{Name: "bad", Protocol: "unknown", Tag: "vpn-bad", Enabled: true, Listen: domain.ListenOptions{ListenPort: 12051}, ProtocolData: []byte("{}")}
		if err := svc.SyncFirewallPortForTest(ctx, vpn, 12051, 12052); err == nil {
			t.Fatal("expected protocol error")
		}
	})

	t.Run("UninstallFullNilFirewall", func(t *testing.T) {
		dir := t.TempDir()
		app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "manifest.json")}
		st := mustOpenStore(t, app.DBPath)
		man := manifest.NewManager(app.ManifestPath)
		_ = man.Load()
		man.AddFirewallRule("1080/tcp")
		_ = man.Save()
		svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, nil, singboxcheck.NopChecker{}, systemd.NopManager{})
		wireStubSSHKeepalive(t, svc, dir)
		svc.SetSysctlForTest(&sysctl.Manager{ConfPath: filepath.Join(dir, "sysctl.conf"), Reload: func() error { return nil }, RemoveFile: os.Remove})
		if err := svc.UninstallFull(ctx, false); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("CreateVPNPrepareProtocolDataError", func(t *testing.T) {
		dir := t.TempDir()
		app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "m.json"), DevMode: true}
		st := mustOpenStore(t, app.DBPath)
		man := manifest.NewManager(app.ManifestPath)
		_ = man.Load()
		reg := customRegistry(t, buildFailProtocol{})
		svc := service.NewService(app, st, reg, man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
		if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{Name: "bf", Protocol: "buildfail", Enabled: false, Listen: domain.ListenOptions{ListenPort: 12055}}); err == nil {
			t.Fatal("expected build error")
		}
	})

	t.Run("UpdateVPNInvalidClientHost", func(t *testing.T) {
		svc, _ := newTestService(t)
		if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{Name: "main", Protocol: "socks5", Enabled: false, Listen: domain.ListenOptions{ListenPort: 12056}}); err != nil {
			t.Fatal(err)
		}
		bad := "not a host!!!"
		if _, err := svc.UpdateVPN(ctx, "main", service.UpdateVPNInput{ClientHost: &bad}, false); err == nil {
			t.Fatal("expected client host error")
		}
	})

	t.Run("UpdateVPNListenPortConflict", func(t *testing.T) {
		svc, _ := newTestService(t)
		if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{Name: "a", Protocol: "socks5", Enabled: true, Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 12057}}); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{Name: "b", Protocol: "socks5", Enabled: false, Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 12058}}); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.UpdateVPN(ctx, "b", service.UpdateVPNInput{Listen: &domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 12057}}, false); err == nil {
			t.Fatal("expected port conflict")
		}
	})

	t.Run("UpdateVPNUnknownProtocol", func(t *testing.T) {
		svc, st := newTestService(t)
		vpn := &domain.VPN{Name: "bad", Protocol: "unknown", Tag: "vpn-bad", Enabled: false, Listen: domain.ListenOptions{ListenPort: 12063}, ProtocolData: []byte("{}")}
		if err := st.CreateVPN(ctx, vpn); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.UpdateVPN(ctx, "bad", service.UpdateVPNInput{}, false); err == nil {
			t.Fatal("expected protocol error")
		}
	})
}
