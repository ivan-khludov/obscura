package service_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/ivan-khludov/obscura/internal/config"
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/firewall"
	"github.com/ivan-khludov/obscura/internal/manifest"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/protocol/shadowsocks"
	"github.com/ivan-khludov/obscura/internal/protocol/wireguard"
	"github.com/ivan-khludov/obscura/internal/runtime"
	"github.com/ivan-khludov/obscura/internal/service"
	"github.com/ivan-khludov/obscura/internal/singboxcheck"
	"github.com/ivan-khludov/obscura/internal/systemd"
)

func TestCreateVPNAndClientApply(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	vpn, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, uri, err := svc.AddClient(ctx, service.AddClientInput{VPNName: vpn.VPN.Name, Name: "phone"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if uri == "" {
		t.Fatal("expected uri")
	}
	result, err := svc.Apply(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Bytes) == 0 {
		t.Fatal("expected config bytes")
	}
}

// TestRotateClientPassword verifies password rotation updates credentials.
func TestRotateClientPassword(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	_, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1081},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = svc.AddClient(ctx, service.AddClientInput{VPNName: "main", Name: "phone"}, false)
	if err != nil {
		t.Fatal(err)
	}
	_, uri, err := svc.RotateClientPassword(ctx, "main", "phone")
	if err != nil {
		t.Fatal(err)
	}
	if uri == "" {
		t.Fatal("expected uri")
	}
}

// TestBootstrapDevSkipsSysctl verifies dev bootstrap does not require sysctl paths.
func TestRemoveClient_LastEnabledRejected(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1090},
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.RemoveClient(ctx, "main", "default"); err == nil {
		t.Fatal("expected error removing last client")
	}
	clients, err := svc.ListClients(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 1 || clients[0].Name != "default" {
		t.Fatalf("client should remain: %#v", clients)
	}
}

// TestRemoveClient_WithRemaining verifies removing one of two clients succeeds.
func TestRemoveClient_WithRemaining(t *testing.T) {
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
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1091},
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "main", Name: "phone"}, false); err != nil {
		t.Fatal(err)
	}
	reloader.called = false
	if err := svc.RemoveClient(ctx, "main", "phone"); err != nil {
		t.Fatal(err)
	}
	if !reloader.called {
		t.Fatal("expected apply reload after remove")
	}
	clients, err := svc.ListClients(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 1 || clients[0].Name != "default" {
		t.Fatalf("unexpected clients: %#v", clients)
	}
}

func TestUpdateClient_Rename(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: true,
		Listen:            domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1096},
		InitialClientName: "phone",
	}); err != nil {
		t.Fatal(err)
	}
	newName := "laptop"
	client, err := svc.UpdateClient(ctx, service.UpdateClientInput{
		VPNName: "main", Name: "phone", NewName: &newName,
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if client.Name != "laptop" {
		t.Fatalf("expected renamed client, got %q", client.Name)
	}
}

// TestUpdateClient_DisableLastEnabledRejected verifies last enabled client cannot be disabled.
func TestUpdateClient_DisableLastEnabledRejected(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: true,
		Listen:            domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1097},
		InitialClientName: "phone",
	}); err != nil {
		t.Fatal(err)
	}
	disabled := false
	if _, err := svc.UpdateClient(ctx, service.UpdateClientInput{
		VPNName: "main", Name: "phone", Enabled: &disabled,
	}, false); err == nil {
		t.Fatal("expected error disabling last enabled client")
	}
}

func TestRemoveDisabledClient(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1098},
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "main", Name: "phone"}, false); err != nil {
		t.Fatal(err)
	}
	disabled := false
	if _, err := svc.UpdateClient(ctx, service.UpdateClientInput{
		VPNName: "main", Name: "phone", Enabled: &disabled,
	}, false); err != nil {
		t.Fatal(err)
	}
	if err := svc.RemoveClient(ctx, "main", "phone"); err != nil {
		t.Fatal(err)
	}
}

func TestAddWireguardClient(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "wg", Protocol: "wireguard", Enabled: false,
		Listen:    domain.ListenOptions{ListenPort: 51821},
		Wireguard: service.WireguardCreateOptions{Address: []string{"10.9.0.1/24"}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "wg", Name: "peer"}, false); err != nil {
		t.Fatal(err)
	}
}

func TestRotateWireguardPassword(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "wg", Protocol: "wireguard", Enabled: true,
		Listen:            domain.ListenOptions{ListenPort: 51822},
		Wireguard:         service.WireguardCreateOptions{Address: []string{"10.9.0.1/24"}},
		InitialClientName: "peer",
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.RotateClientPassword(ctx, "wg", "peer"); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateClientDuplicateName(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{ListenPort: 1099},
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "main", Name: "phone"}, false); err != nil {
		t.Fatal(err)
	}
	dup := "phone"
	if _, err := svc.UpdateClient(ctx, service.UpdateClientInput{
		VPNName: "main", Name: "default", NewName: &dup,
	}, false); err == nil {
		t.Fatal("expected duplicate name error")
	}
}

func TestClientURINotFound(t *testing.T) {
	svc, _ := newTestService(t)
	if _, err := svc.ClientURI(context.Background(), "missing", "x"); err == nil {
		t.Fatal("expected error")
	}
}

func TestAddClientExplicitCredentials(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{ListenPort: 11001},
	}); err != nil {
		t.Fatal(err)
	}
	client, uri, err := svc.AddClient(ctx, service.AddClientInput{
		VPNName: "main", Name: "custom", Username: "alice", Password: "secret",
	}, false)
	if err != nil || client.Username != "alice" || uri == "" {
		t.Fatalf("client=%#v uri=%q err=%v", client, uri, err)
	}
	qr, err := svc.ClientQRContent(ctx, "main", "custom")
	if err != nil || qr == "" {
		t.Fatalf("qr=%q err=%v", qr, err)
	}
}

func TestAddTUICClient(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "tc", Protocol: "tuic", Enabled: false,
		Listen: domain.ListenOptions{ListenPort: 11002},
		TUIC:   service.TUICCreateOptions{ServerName: "example.com"},
	}); err != nil {
		t.Fatal(err)
	}
	client, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "tc", Name: "phone"}, false)
	if err != nil || client.Username == "" {
		t.Fatalf("client=%#v err=%v", client, err)
	}
}

func TestClientErrors(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "missing", Name: "x"}, false); err == nil {
		t.Fatal("expected missing vpn")
	}
	if _, err := svc.ListClients(ctx, "missing"); err == nil {
		t.Fatal("expected list clients error")
	}
	if _, err := svc.ClientQRContent(ctx, "missing", "x"); err == nil {
		t.Fatal("expected qr error")
	}
}

func TestAddClientPasswordGenError(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: false,
		Listen: domain.ListenOptions{ListenPort: 11010},
	}); err != nil {
		t.Fatal(err)
	}
	svc.SetPasswordGenForTest(service.PasswordGen{RandRead: errReader{}})
	if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "main", Name: "x"}, false); err == nil {
		t.Fatal("expected password error")
	}
}

func TestAddClientApplyError(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: true, ServerHost: "127.0.0.1",
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, failChecker{}, applyFailReload{})
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: false,
		Listen: domain.ListenOptions{ListenPort: 11011},
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "main", Name: "phone"}, true); err == nil {
		t.Fatal("expected apply error")
	}
}

func TestAddClientInvalidProtocol(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: true,
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	reg := customRegistry(t, invalidClientProtocol{})
	svc := service.NewService(app, st, reg, man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	ctx := context.Background()
	vpn := &domain.VPN{Name: "bad", Protocol: "badclient", Tag: "vpn-bad", Enabled: false, Listen: domain.ListenOptions{ListenPort: 11012}, ProtocolData: []byte("{}")}
	if err := st.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "bad", Name: "x"}, false); err == nil {
		t.Fatal("expected validate client error")
	}
}

func TestAddClientURIFail(t *testing.T) {
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
	vpn := &domain.VPN{Name: "uri", Protocol: "urifail", Tag: "vpn-uri", Enabled: false, Listen: domain.ListenOptions{ListenPort: 11013}, ProtocolData: []byte("{}")}
	if err := st.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "uri", Name: "x"}, false); err == nil {
		t.Fatal("expected uri error")
	}
}

func TestAddClientAutoUsername(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: false,
		Listen: domain.ListenOptions{ListenPort: 11014},
	}); err != nil {
		t.Fatal(err)
	}
	client, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "main", Name: "My Phone"}, false)
	if err != nil || client.Username == "" {
		t.Fatalf("client=%#v err=%v", client, err)
	}
}

func TestAddClientEmptyNameUsername(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: false,
		Listen: domain.ListenOptions{ListenPort: 11015},
	}); err != nil {
		t.Fatal(err)
	}
	client, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "main", Name: ""}, false)
	if err != nil || client.Username == "" {
		t.Fatalf("client=%#v err=%v", client, err)
	}
}

func TestAddWireguardClientKeyGenError(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "wg", Protocol: "wireguard", Enabled: false,
		Listen:    domain.ListenOptions{ListenPort: 51823},
		Wireguard: service.WireguardCreateOptions{Address: []string{"10.9.0.1/24"}},
	}); err != nil {
		t.Fatal(err)
	}
	svc.SetWireguardKeyGenForTest(service.WireguardKeyGen{GenerateKeypair: func() (wireguard.Keypair, error) {
		return wireguard.Keypair{}, fmt.Errorf("keygen failed")
	}})
	if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "wg", Name: "peer"}, false); err == nil {
		t.Fatal("expected keygen error")
	}
}

func TestRotateClientPasswordErrors(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, _, err := svc.RotateClientPassword(ctx, "missing", "x"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: false,
		Listen: domain.ListenOptions{ListenPort: 11016},
	}); err != nil {
		t.Fatal(err)
	}
	svc.SetPasswordGenForTest(service.PasswordGen{RandRead: errReader{}})
	if _, _, err := svc.RotateClientPassword(ctx, "main", "default"); err == nil {
		t.Fatal("expected password error")
	}
}

func TestUpdateClientErrors(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	empty := ""
	if _, err := svc.UpdateClient(ctx, service.UpdateClientInput{VPNName: "missing", Name: "x", NewName: &empty}, false); err == nil {
		t.Fatal("expected missing vpn")
	}
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: false,
		Listen: domain.ListenOptions{ListenPort: 11017},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateClient(ctx, service.UpdateClientInput{VPNName: "main", Name: "missing"}, false); err == nil {
		t.Fatal("expected missing client")
	}
	blank := "  "
	if _, err := svc.UpdateClient(ctx, service.UpdateClientInput{VPNName: "main", Name: "default", NewName: &blank}, false); err == nil {
		t.Fatal("expected empty name error")
	}
	if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "main", Name: "phone", Username: "bob"}, false); err != nil {
		t.Fatal(err)
	}
	dupUser := "bob"
	if _, err := svc.UpdateClient(ctx, service.UpdateClientInput{VPNName: "main", Name: "default", Username: &dupUser}, false); err == nil {
		t.Fatal("expected duplicate username")
	}
}

func TestUpdateClientApplyError(t *testing.T) {
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
		Listen: domain.ListenOptions{ListenPort: 11018},
	}); err != nil {
		t.Fatal(err)
	}
	newName := "renamed"
	if _, err := svc.UpdateClient(ctx, service.UpdateClientInput{VPNName: "main", Name: "default", NewName: &newName}, true); err == nil {
		t.Fatal("expected apply error")
	}
}

func TestRemoveClientErrors(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if err := svc.RemoveClient(ctx, "missing", "x"); err == nil {
		t.Fatal("expected error")
	}
}

func TestGenerateClientPasswordShadowsocksError(t *testing.T) {
	svc, _ := newTestService(t)
	_, err := svc.GenerateClientPasswordForTest(&domain.VPN{Protocol: "shadowsocks", ProtocolData: []byte("bad")})
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestClientOperationsClosedStore(t *testing.T) {
	svc := closedStoreService(t)
	ctx := context.Background()
	if _, err := svc.ListClients(ctx, "main"); err == nil {
		t.Fatal("expected store error")
	}
}

func TestClientURIsAfterStoreClose(t *testing.T) {
	svc, st := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: false,
		Listen: domain.ListenOptions{ListenPort: 11020},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ClientURI(ctx, "main", "default"); err == nil {
		t.Fatal("expected uri error")
	}
	if _, err := svc.ClientQRContent(ctx, "main", "default"); err == nil {
		t.Fatal("expected qr error")
	}
}

func TestRotateClientPasswordWireguardKeyError(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "wg", Protocol: "wireguard", Enabled: false,
		Listen:    domain.ListenOptions{ListenPort: 51824},
		Wireguard: service.WireguardCreateOptions{Address: []string{"10.9.0.1/24"}},
	}); err != nil {
		t.Fatal(err)
	}
	svc.SetWireguardKeyGenForTest(service.WireguardKeyGen{GenerateKeypair: func() (wireguard.Keypair, error) {
		return wireguard.Keypair{PrivateKey: "not-valid-key", PublicKey: "x"}, nil
	}})
	if _, _, err := svc.RotateClientPassword(ctx, "wg", "default"); err == nil {
		t.Fatal("expected pubkey error")
	}
}

func TestRotateClientPasswordApplyError(t *testing.T) {
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
		Listen: domain.ListenOptions{ListenPort: 11021},
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.RotateClientPassword(ctx, "main", "default"); err == nil {
		t.Fatal("expected apply error")
	}
}

func TestRemoveClientApplyError(t *testing.T) {
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
		Listen: domain.ListenOptions{ListenPort: 11022},
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "main", Name: "phone"}, false); err != nil {
		t.Fatal(err)
	}
	enabled := true
	if _, err := svc.UpdateVPN(ctx, "main", service.UpdateVPNInput{Enabled: &enabled}, false); err != nil {
		t.Fatal(err)
	}
	if err := svc.RemoveClient(ctx, "main", "phone"); err == nil {
		t.Fatal("expected apply error")
	}
}

func TestGenerateClientPasswordWireguardError(t *testing.T) {
	svc, _ := newTestService(t)
	svc.SetWireguardKeyGenForTest(service.WireguardKeyGen{GenerateKeypair: func() (wireguard.Keypair, error) {
		return wireguard.Keypair{}, fmt.Errorf("fail")
	}})
	_, err := svc.GenerateClientPasswordForTest(&domain.VPN{Protocol: "wireguard"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClientStoreFaults(t *testing.T) {
	ctx := context.Background()
	storeErr := fmt.Errorf("store failed")

	t.Run("AddClientCreateClient", func(t *testing.T) {
		svc, st := newTestService(t)
		vpn := &domain.VPN{Name: "main", Protocol: "socks5", Tag: "vpn-main", Enabled: false, Listen: domain.ListenOptions{ListenPort: 11030}, ProtocolData: []byte("{}")}
		if err := st.CreateVPN(ctx, vpn); err != nil {
			t.Fatal(err)
		}
		fs := wrapFaultStore(st)
		fs.createClientErr = storeErr
		svc.SetStoreForTest(fs)
		if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "main", Name: "x"}, false); err == nil {
			t.Fatal("expected create client error")
		}
	})

	t.Run("AddClientListClients", func(t *testing.T) {
		svc, st := newTestService(t)
		fs := wrapFaultStore(st)
		if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{Name: "main", Protocol: "socks5", Enabled: false, Listen: domain.ListenOptions{ListenPort: 11031}}); err != nil {
			t.Fatal(err)
		}
		fs.listClientsErr = storeErr
		svc.SetStoreForTest(fs)
		if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "main", Name: "x"}, false); err == nil {
			t.Fatal("expected list clients error")
		}
	})

	t.Run("ClientURIMissingClient", func(t *testing.T) {
		svc, _ := newTestService(t)
		if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{Name: "main", Protocol: "socks5", Enabled: false, Listen: domain.ListenOptions{ListenPort: 11032}}); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.ClientURI(ctx, "main", "missing"); err == nil {
			t.Fatal("expected missing client")
		}
	})

	t.Run("ClientURIListClients", func(t *testing.T) {
		svc, st := newTestService(t)
		if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{Name: "main", Protocol: "socks5", Enabled: false, Listen: domain.ListenOptions{ListenPort: 11033}}); err != nil {
			t.Fatal(err)
		}
		fs := wrapFaultStore(st)
		fs.listClientsErr = storeErr
		svc.SetStoreForTest(fs)
		if _, err := svc.ClientURI(ctx, "main", "default"); err == nil {
			t.Fatal("expected list error")
		}
	})

	t.Run("RemoveDisabledClientDelete", func(t *testing.T) {
		svc, st := newTestService(t)
		if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{Name: "main", Protocol: "socks5", Enabled: false, Listen: domain.ListenOptions{ListenPort: 11034}}); err != nil {
			t.Fatal(err)
		}
		disabled := false
		if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "main", Name: "phone"}, false); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.UpdateClient(ctx, service.UpdateClientInput{VPNName: "main", Name: "phone", Enabled: &disabled}, false); err != nil {
			t.Fatal(err)
		}
		fs := wrapFaultStore(st)
		fs.deleteClientErr = storeErr
		svc.SetStoreForTest(fs)
		if err := svc.RemoveClient(ctx, "main", "phone"); err == nil {
			t.Fatal("expected delete error")
		}
	})

	t.Run("UpdateClientListClients", func(t *testing.T) {
		svc, st := newTestService(t)
		if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{Name: "main", Protocol: "socks5", Enabled: false, Listen: domain.ListenOptions{ListenPort: 11035}}); err != nil {
			t.Fatal(err)
		}
		fs := wrapFaultStore(st)
		fs.listClientsErr = storeErr
		svc.SetStoreForTest(fs)
		if _, err := svc.UpdateClient(ctx, service.UpdateClientInput{VPNName: "main", Name: "default"}, false); err == nil {
			t.Fatal("expected list error")
		}
	})

	t.Run("UpdateClientUpdateStore", func(t *testing.T) {
		svc, st := newTestService(t)
		if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{Name: "main", Protocol: "socks5", Enabled: false, Listen: domain.ListenOptions{ListenPort: 11036}}); err != nil {
			t.Fatal(err)
		}
		fs := wrapFaultStore(st)
		fs.updateClientErr = storeErr
		svc.SetStoreForTest(fs)
		user := "alice"
		if _, err := svc.UpdateClient(ctx, service.UpdateClientInput{VPNName: "main", Name: "default", Username: &user}, false); err == nil {
			t.Fatal("expected update error")
		}
	})

	t.Run("RotateUpdateClient", func(t *testing.T) {
		svc, st := newTestService(t)
		if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{Name: "main", Protocol: "socks5", Enabled: false, Listen: domain.ListenOptions{ListenPort: 11037}}); err != nil {
			t.Fatal(err)
		}
		fs := wrapFaultStore(st)
		fs.updateClientErr = storeErr
		svc.SetStoreForTest(fs)
		if _, _, err := svc.RotateClientPassword(ctx, "main", "default"); err == nil {
			t.Fatal("expected update error")
		}
	})

	t.Run("AddClientUnknownProtocol", func(t *testing.T) {
		svc, st := newTestService(t)
		vpn := &domain.VPN{Name: "bad", Protocol: "unknown", Tag: "vpn-bad", Enabled: false, Listen: domain.ListenOptions{ListenPort: 11038}, ProtocolData: []byte("{}")}
		if err := st.CreateVPN(ctx, vpn); err != nil {
			t.Fatal(err)
		}
		if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "bad", Name: "x"}, false); err == nil {
			t.Fatal("expected protocol error")
		}
	})

	t.Run("AddClientValidateVPN", func(t *testing.T) {
		dir := t.TempDir()
		app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "m.json"), DevMode: true}
		st := mustOpenStore(t, app.DBPath)
		man := manifest.NewManager(app.ManifestPath)
		_ = man.Load()
		reg := customRegistry(t, validateVPNFailProtocol{})
		svc := service.NewService(app, st, reg, man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
		vpn := &domain.VPN{Name: "vf", Protocol: "valfail", Tag: "vpn-vf", Enabled: false, Listen: domain.ListenOptions{ListenPort: 11040}, ProtocolData: []byte("{}")}
		if err := st.CreateVPN(ctx, vpn); err != nil {
			t.Fatal(err)
		}
		if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "vf", Name: "x"}, false); err == nil {
			t.Fatal("expected validate vpn error")
		}
	})

	t.Run("RemoveClientMissingClient", func(t *testing.T) {
		svc, _ := newTestService(t)
		if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{Name: "main", Protocol: "socks5", Enabled: false, Listen: domain.ListenOptions{ListenPort: 11041}}); err != nil {
			t.Fatal(err)
		}
		if err := svc.RemoveClient(ctx, "main", "missing"); err == nil {
			t.Fatal("expected missing client")
		}
	})

	t.Run("RemoveClientListRemainingError", func(t *testing.T) {
		svc, st := newTestService(t)
		if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{Name: "main", Protocol: "socks5", Enabled: true, Listen: domain.ListenOptions{ListenPort: 11042}}); err != nil {
			t.Fatal(err)
		}
		fs := wrapFaultStore(st)
		fs.listEnabledClientsErr = storeErr
		svc.SetStoreForTest(fs)
		if err := svc.RemoveClient(ctx, "main", "default"); err == nil {
			t.Fatal("expected list error")
		}
	})

	t.Run("UpdateClientPassword", func(t *testing.T) {
		svc, _ := newTestService(t)
		if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{Name: "main", Protocol: "socks5", Enabled: false, Listen: domain.ListenOptions{ListenPort: 11043}}); err != nil {
			t.Fatal(err)
		}
		pass := "secret"
		if _, err := svc.UpdateClient(ctx, service.UpdateClientInput{VPNName: "main", Name: "default", Password: &pass}, false); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("ClientURIUnknownProtocol", func(t *testing.T) {
		svc, st := newTestService(t)
		vpn := &domain.VPN{Name: "bad", Protocol: "unknown", Tag: "vpn-bad", Enabled: false, Listen: domain.ListenOptions{ListenPort: 11050}, ProtocolData: []byte("{}")}
		if err := st.CreateVPN(ctx, vpn); err != nil {
			t.Fatal(err)
		}
		if err := st.CreateClient(ctx, &domain.Client{VPNID: vpn.ID, Name: "c", Username: "u", Password: "p", Enabled: true}); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.ClientURI(ctx, "bad", "c"); err == nil {
			t.Fatal("expected protocol error")
		}
		if _, err := svc.ClientQRContent(ctx, "bad", "c"); err == nil {
			t.Fatal("expected protocol error")
		}
	})

	t.Run("RemoveClientDeleteApplyError", func(t *testing.T) {
		dir := t.TempDir()
		app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "m.json"), DevMode: true}
		st := mustOpenStore(t, app.DBPath)
		man := manifest.NewManager(app.ManifestPath)
		_ = man.Load()
		svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, applyFailReload{})
		if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{Name: "main", Protocol: "socks5", Enabled: false, Listen: domain.ListenOptions{ListenPort: 11051}}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "main", Name: "phone"}, false); err != nil {
			t.Fatal(err)
		}
		enabled := true
		if _, err := svc.UpdateVPN(ctx, "main", service.UpdateVPNInput{Enabled: &enabled}, false); err != nil {
			t.Fatal(err)
		}
		if err := svc.RemoveClient(ctx, "main", "phone"); err == nil {
			t.Fatal("expected apply error")
		}
	})
}

func TestGenerateClientPasswordShadowsocksEmptyMethod(t *testing.T) {
	svc, _ := newTestService(t)
	raw, err := svc.BuildProtocolDataForTest(service.CreateVPNInput{
		Name: "ss", Protocol: "shadowsocks",
		Listen: domain.ListenOptions{ListenPort: 8388},
	}, "vpn-ss", protocol.BuildModeProvision)
	if err != nil {
		t.Fatal(err)
	}
	data, err := shadowsocks.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	data.Method = ""
	raw, err = shadowsocks.MarshalProtocolData(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GenerateClientPasswordForTest(&domain.VPN{Protocol: "shadowsocks", ProtocolData: raw}); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateClientPasswordVmess(t *testing.T) {
	svc, _ := newTestService(t)
	pw, err := svc.GenerateClientPasswordForTest(&domain.VPN{Protocol: "vmess"})
	if err != nil || pw == "" {
		t.Fatalf("password=%q err=%v", pw, err)
	}
}

func TestRemoveDisabledClientApplyError(t *testing.T) {
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
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{Name: "main", Protocol: "socks5", Enabled: false, Listen: domain.ListenOptions{ListenPort: 11050}}); err != nil {
		t.Fatal(err)
	}
	disabled := false
	if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "main", Name: "phone"}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateClient(ctx, service.UpdateClientInput{VPNName: "main", Name: "phone", Enabled: &disabled}, false); err != nil {
		t.Fatal(err)
	}
	if err := svc.RemoveClient(ctx, "main", "phone"); err == nil {
		t.Fatal("expected apply error")
	}
}

func TestClientQRUnknownProtocol(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "m.json"), DevMode: true}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	reg := customRegistry(t, qrFailProtocol{})
	svc := service.NewService(app, st, reg, man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	ctx := context.Background()
	vpn := &domain.VPN{Name: "qr", Protocol: "qrfail", Tag: "vpn-qr", Enabled: false, Listen: domain.ListenOptions{ListenPort: 11051}, ProtocolData: []byte("{}")}
	if err := st.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateClient(ctx, &domain.Client{VPNID: vpn.ID, Name: "c", Username: "u", Password: "p", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ClientQRContent(ctx, "qr", "c"); err == nil {
		t.Fatal("expected qr error")
	}
}

func TestClientURIUnknownProtocol(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "m.json"), DevMode: true}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	reg := customRegistry(t, uriFailProtocol{})
	svc := service.NewService(app, st, reg, man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	ctx := context.Background()
	vpn := &domain.VPN{Name: "uri", Protocol: "urifail", Tag: "vpn-uri", Enabled: false, Listen: domain.ListenOptions{ListenPort: 11052}, ProtocolData: []byte("{}")}
	if err := st.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateClient(ctx, &domain.Client{VPNID: vpn.ID, Name: "c", Username: "u", Password: "p", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ClientURI(ctx, "uri", "c"); err == nil {
		t.Fatal("expected uri error")
	}
}

func TestUpdateClientValidateVPNError(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "m.json"), DevMode: true}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	reg := customRegistry(t, validateVPNFailProtocol{})
	svc := service.NewService(app, st, reg, man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	ctx := context.Background()
	vpn := &domain.VPN{Name: "vf", Protocol: "valfail", Tag: "vpn-vf", Enabled: false, Listen: domain.ListenOptions{ListenPort: 11053}, ProtocolData: []byte("{}")}
	if err := st.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateClient(ctx, &domain.Client{VPNID: vpn.ID, Name: "c", Username: "u", Password: "p", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	user := "bob"
	if _, err := svc.UpdateClient(ctx, service.UpdateClientInput{VPNName: "vf", Name: "c", Username: &user}, false); err == nil {
		t.Fatal("expected validate vpn error")
	}
}

func TestRemoveClientDeleteEnabledError(t *testing.T) {
	svc, st := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{Name: "main", Protocol: "socks5", Enabled: true, Listen: domain.ListenOptions{ListenPort: 11054}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "main", Name: "phone"}, false); err != nil {
		t.Fatal(err)
	}
	fs := wrapFaultStore(st)
	fs.deleteClientErr = fmt.Errorf("delete failed")
	svc.SetStoreForTest(fs)
	if err := svc.RemoveClient(ctx, "main", "phone"); err == nil {
		t.Fatal("expected delete error")
	}
}

func TestRotateClientPasswordURIError(t *testing.T) {
	svc, st := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{Name: "main", Protocol: "socks5", Enabled: false, Listen: domain.ListenOptions{ListenPort: 11055}}); err != nil {
		t.Fatal(err)
	}
	fs := wrapFaultStore(st)
	fs.listClientsErr = fmt.Errorf("list failed")
	svc.SetStoreForTest(fs)
	if _, _, err := svc.RotateClientPassword(ctx, "main", "default"); err == nil {
		t.Fatal("expected uri error")
	}
}

func TestClientURIGetClientError(t *testing.T) {
	svc, st := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{Name: "main", Protocol: "socks5", Enabled: false, Listen: domain.ListenOptions{ListenPort: 11056}}); err != nil {
		t.Fatal(err)
	}
	fs := wrapFaultStore(st)
	fs.getClientByNameErr = fmt.Errorf("missing")
	svc.SetStoreForTest(fs)
	if _, err := svc.ClientURI(ctx, "main", "default"); err == nil {
		t.Fatal("expected get client error")
	}
	if _, err := svc.ClientQRContent(ctx, "main", "default"); err == nil {
		t.Fatal("expected get client error")
	}
}

func TestClientURIRegistryError(t *testing.T) {
	svc, st := newTestService(t)
	ctx := context.Background()
	vpn := &domain.VPN{Name: "bad", Protocol: "unknown", Tag: "vpn-bad", Enabled: false, Listen: domain.ListenOptions{ListenPort: 11057}, ProtocolData: []byte("{}")}
	if err := st.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateClient(ctx, &domain.Client{VPNID: vpn.ID, Name: "c", Username: "u", Password: "p", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ClientURI(ctx, "bad", "c"); err == nil {
		t.Fatal("expected protocol error")
	}
	if _, err := svc.ClientQRContent(ctx, "bad", "c"); err == nil {
		t.Fatal("expected protocol error")
	}
}

func TestGenerateClientPasswordVless(t *testing.T) {
	svc, _ := newTestService(t)
	pw, err := svc.GenerateClientPasswordForTest(&domain.VPN{Protocol: "vless"})
	if err != nil || pw == "" {
		t.Fatalf("password=%q err=%v", pw, err)
	}
}

func TestRotateClientPasswordMissingClient(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{Name: "main", Protocol: "socks5", Enabled: false, Listen: domain.ListenOptions{ListenPort: 11058}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.RotateClientPassword(ctx, "main", "missing"); err == nil {
		t.Fatal("expected missing client")
	}
}

func TestUpdateClientUnknownProtocol(t *testing.T) {
	svc, st := newTestService(t)
	ctx := context.Background()
	vpn := &domain.VPN{Name: "bad", Protocol: "unknown", Tag: "vpn-bad", Enabled: false, Listen: domain.ListenOptions{ListenPort: 11059}, ProtocolData: []byte("{}")}
	if err := st.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateClient(ctx, &domain.Client{VPNID: vpn.ID, Name: "c", Username: "u", Password: "p", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateClient(ctx, service.UpdateClientInput{VPNName: "bad", Name: "c"}, false); err == nil {
		t.Fatal("expected protocol error")
	}
}

func TestUpdateClientInvalidClient(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "m.json"), DevMode: true}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	reg := customRegistry(t, invalidClientProtocol{})
	svc := service.NewService(app, st, reg, man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	ctx := context.Background()
	vpn := &domain.VPN{Name: "bad", Protocol: "badclient", Tag: "vpn-bad", Enabled: false, Listen: domain.ListenOptions{ListenPort: 11060}, ProtocolData: []byte("{}")}
	if err := st.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateClient(ctx, &domain.Client{VPNID: vpn.ID, Name: "c", Username: "u", Password: "p", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	user := "bob"
	if _, err := svc.UpdateClient(ctx, service.UpdateClientInput{VPNName: "bad", Name: "c", Username: &user}, false); err == nil {
		t.Fatal("expected validate client error")
	}
}

func TestClientQRContentListClientsError(t *testing.T) {
	svc, st := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{Name: "main", Protocol: "socks5", Enabled: false, Listen: domain.ListenOptions{ListenPort: 11061}}); err != nil {
		t.Fatal(err)
	}
	fs := wrapFaultStore(st)
	fs.listClientsErr = fmt.Errorf("list failed")
	svc.SetStoreForTest(fs)
	if _, err := svc.ClientQRContent(ctx, "main", "default"); err == nil {
		t.Fatal("expected list error")
	}
}
