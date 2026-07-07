package service_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/config"
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/firewall"
	"github.com/ivan-khludov/obscura/internal/manifest"
	"github.com/ivan-khludov/obscura/internal/runtime"
	"github.com/ivan-khludov/obscura/internal/service"
	"github.com/ivan-khludov/obscura/internal/singboxcheck"
	"github.com/ivan-khludov/obscura/internal/sshd"
	"github.com/ivan-khludov/obscura/internal/systemd"
)

func TestSetSSHPortDevMode(t *testing.T) {
	svc, _ := newTestService(t)
	if err := svc.SetSSHPort(context.Background(), 2222); err == nil {
		t.Fatal("expected dev mode error")
	}
}

// TestSetSSHPortVPNConflict verifies SSH port cannot move to an enabled VPN listen port.
func TestSetSSHPortVPNConflict(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir:      dir,
		DBPath:       filepath.Join(dir, "state.db"),
		ConfigPath:   filepath.Join(dir, "sing-box.json"),
		ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode:      false,
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
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 2222},
	}); err != nil {
		t.Fatal(err)
	}
	err := svc.SetSSHPort(ctx, 2222)
	if err == nil {
		t.Fatal("expected error when SSH port conflicts with VPN")
	}
	if !strings.Contains(err.Error(), "main") {
		t.Fatalf("expected VPN name in error, got: %v", err)
	}
}

func TestSSHPortAndSync(t *testing.T) {
	svc, _ := newTestService(t)
	if port := svc.SSHPort(); port != 22 {
		t.Fatalf("expected default 22, got %d", port)
	}
	svc.SyncSSHPortFromSystemForTest()
	fw := &trackingFirewall{}
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	man.AddFirewallRule("22/tcp")
	_ = man.Save()
	svc2 := service.NewService(app, st, runtime.NewProtocolRegistry(), man, fw, singboxcheck.NopChecker{}, systemd.NopManager{})
	ctx := context.Background()
	svc2.SyncSSHFirewallForTest(ctx, 22, 2222)
	if len(fw.allowed) == 0 {
		t.Fatal("expected firewall allow")
	}
}

func TestSetSSHPortSamePortNoOp(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: false,
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	man.SetSSHPort(22)
	_ = man.Save()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SetRootCheckForTest(func() bool { return true })
	if err := svc.SetSSHPort(context.Background(), 22); err != nil {
		t.Fatal(err)
	}
}

func TestSetSSHPortSuccess(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(cfgPath, []byte("Port 22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: false,
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	man.SetSSHPort(22)
	_ = man.Save()
	fw := &trackingFirewall{}
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, fw, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SetRootCheckForTest(func() bool { return true })
	cfg := &sshd.Config{
		ReadFile:  os.ReadFile,
		WriteFile: os.WriteFile,
	}
	run := &sshd.Runner{
		RunCommand: func(context.Context, string, ...string) ([]byte, error) { return nil, nil },
	}
	svc.SetSSHDForTest(cfgPath, cfg, run)
	if err := svc.SetSSHPort(context.Background(), 2222); err != nil {
		t.Fatal(err)
	}
	if svc.SSHPort() != 2222 {
		t.Fatalf("port=%d", svc.SSHPort())
	}
}

func TestSetSSHPortInvalid(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "m.json"), DevMode: false}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SetRootCheckForTest(func() bool { return true })
	if err := svc.SetSSHPort(context.Background(), 0); err == nil {
		t.Fatal("expected invalid port")
	}
}

func TestSSHPortFromConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(cfgPath, []byte("Port 2222\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "m.json"), DevMode: true}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SetSSHDForTest(cfgPath, &sshd.Config{ReadFile: os.ReadFile, WriteFile: os.WriteFile}, nil)
	if port := svc.SSHPort(); port != 2222 {
		t.Fatalf("port=%d", port)
	}
}

func TestSetSSHPortTestConfigFail(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(cfgPath, []byte("Port 22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: false,
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SetRootCheckForTest(func() bool { return true })
	cfg := &sshd.Config{ReadFile: os.ReadFile, WriteFile: os.WriteFile}
	run := &sshd.Runner{RunCommand: func(context.Context, string, ...string) ([]byte, error) {
		return []byte("bad"), fmt.Errorf("sshd -t failed")
	}}
	svc.SetSSHDForTest(cfgPath, cfg, run)
	if err := svc.SetSSHPort(context.Background(), 2222); err == nil {
		t.Fatal("expected test config failure")
	}
}

func TestSetSSHPortReloadFail(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(cfgPath, []byte("Port 22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: false,
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SetRootCheckForTest(func() bool { return true })
	cfg := &sshd.Config{ReadFile: os.ReadFile, WriteFile: os.WriteFile}
	calls := 0
	run := &sshd.Runner{RunCommand: func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "sshd" {
			return nil, nil
		}
		calls++
		return nil, fmt.Errorf("reload failed")
	}}
	svc.SetSSHDForTest(cfgPath, cfg, run)
	if err := svc.SetSSHPort(context.Background(), 2222); err == nil {
		t.Fatal("expected reload failure")
	}
}

type deleteFailFirewall struct{ trackingFirewall }

func (deleteFailFirewall) DeleteRule(_ context.Context, _ string) error {
	return fmt.Errorf("delete failed")
}

func TestSetSSHPortRequiresRoot(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: false,
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SetRootCheckForTest(func() bool { return false })
	if err := svc.SetSSHPort(context.Background(), 2222); err == nil {
		t.Fatal("expected root error")
	}
}

func TestSSHPortReadConfigError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(cfgPath, []byte("Port 22\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(cfgPath, 0o644) })
	app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "m.json"), DevMode: true}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SetSSHDForTest(cfgPath, &sshd.Config{ReadFile: os.ReadFile}, nil)
	if port := svc.SSHPort(); port != 22 {
		t.Fatalf("port=%d", port)
	}
}

func TestSetSSHPortVPNConflictClosedStore(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: false,
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SetRootCheckForTest(func() bool { return true })
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetSSHPort(context.Background(), 2222); err == nil {
		t.Fatal("expected error")
	}
}

func TestSyncSSHFirewallSamePort(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "m.json")}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, &trackingFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SyncSSHFirewallForTest(context.Background(), 22, 22)
}

func TestSyncSSHPortFromSystemReadsConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(cfgPath, []byte("Port 2225\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "m.json"), DevMode: true}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SetSSHDForTest(cfgPath, &sshd.Config{ReadFile: os.ReadFile, WriteFile: os.WriteFile}, nil)
	svc.SyncSSHPortFromSystemForTest()
	if svc.SSHPort() != 2225 {
		t.Fatalf("port=%d", svc.SSHPort())
	}
}

func TestSyncSSHFirewallDeleteError(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "m.json")}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	man.AddFirewallRule("22/tcp")
	_ = man.Save()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, &deleteFailFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SyncSSHFirewallForTest(context.Background(), 22, 2222)
}

func TestSSHPortFromManifest(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "m.json"), DevMode: true}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	man.SetSSHPort(2222)
	_ = man.Save()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	if port := svc.SSHPort(); port != 2222 {
		t.Fatalf("port=%d", port)
	}
}

func TestSyncSSHPortFromSystemReadError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(cfgPath, []byte("Port 22\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(cfgPath, 0o644) })
	app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "m.json"), DevMode: true}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SetSSHDForTest(cfgPath, &sshd.Config{ReadFile: os.ReadFile}, nil)
	svc.SyncSSHPortFromSystemForTest()
	if svc.SSHPort() != 22 {
		t.Fatalf("port=%d", svc.SSHPort())
	}
}

func TestSyncSSHFirewallAllowError(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "m.json")}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, &allowFailFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SyncSSHFirewallForTest(context.Background(), 22, 2222)
}

func TestSyncSSHPortFromSystemSuccess(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(cfgPath, []byte("Port 2222\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "m.json"), DevMode: true}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SetSSHDForTest(cfgPath, &sshd.Config{ReadFile: os.ReadFile, WriteFile: os.WriteFile}, nil)
	svc.SyncSSHPortFromSystemForTest()
	if svc.SSHPort() != 2222 {
		t.Fatalf("port=%d", svc.SSHPort())
	}
}

func TestSyncSSHFirewallDeleteSuccess(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "m.json")}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	man.AddFirewallRule("22/tcp")
	_ = man.Save()
	fw := &trackingFirewall{}
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, fw, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SyncSSHFirewallForTest(context.Background(), 22, 2222)
	if len(fw.deleted) != 1 {
		t.Fatalf("deleted=%#v", fw.deleted)
	}
}

func TestSyncSSHFirewallUnavailable(t *testing.T) {
	svc, _ := newTestService(t)
	svc.SyncSSHFirewallForTest(context.Background(), 22, 2222)
}
