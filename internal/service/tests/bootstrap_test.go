package service_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ivan-khludov/obscura/internal/config"
	"github.com/ivan-khludov/obscura/internal/firewall"
	"github.com/ivan-khludov/obscura/internal/install"
	"github.com/ivan-khludov/obscura/internal/manifest"
	"github.com/ivan-khludov/obscura/internal/render"
	"github.com/ivan-khludov/obscura/internal/runtime"
	"github.com/ivan-khludov/obscura/internal/service"
	"github.com/ivan-khludov/obscura/internal/singboxcheck"
	"github.com/ivan-khludov/obscura/internal/sysctl"
	"github.com/ivan-khludov/obscura/internal/systemd"
)

func TestBootstrapDevSkipsSysctl(t *testing.T) {
	svc, _ := newTestService(t)
	if err := svc.Bootstrap(context.Background(), service.BootstrapOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapEnablesFirewall(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	fw := &trackingFirewall{}
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, fw, singboxcheck.NopChecker{}, systemd.NopManager{})
	if err := svc.EnableBootstrapFirewall(context.Background(), service.BootstrapOptions{}); err != nil {
		t.Fatal(err)
	}
	if !fw.enabled || fw.enablePort != 22 {
		t.Fatalf("firewall=%#v", fw)
	}
}

func TestBootstrapWritesInitialConfig(t *testing.T) {
	svc, _ := newTestService(t)
	if err := svc.Bootstrap(context.Background(), service.BootstrapOptions{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(svc.DataDir(), "sing-box.json"))
	if err != nil || len(data) == 0 || data[0] != '{' {
		t.Fatalf("config: %q err=%v", data, err)
	}
}

func TestIsBootstrapped(t *testing.T) {
	svc, _ := newTestService(t)
	if svc.IsBootstrapped() {
		t.Fatal("expected not bootstrapped")
	}
	if err := svc.Bootstrap(context.Background(), service.BootstrapOptions{}); err != nil {
		t.Fatal(err)
	}
	if !svc.IsBootstrapped() {
		t.Fatal("expected bootstrapped")
	}
}

func TestBootstrapWithFallbackStubDev(t *testing.T) {
	svc, _ := newTestService(t)
	if err := svc.Bootstrap(context.Background(), service.BootstrapOptions{WithFallbackStub: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(svc.DataDir(), "fallback", "site", "index.html")); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapProdPaths(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: false, ServerHost: "127.0.0.1",
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	fw := &trackingFirewall{}
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, fw, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SetRootCheckForTest(func() bool { return true })
	svc.SetSysctlForTest(&sysctl.Manager{ConfPath: filepath.Join(dir, "99-obscura.conf"), Reload: func() error { return nil }})
	svc.SetSystemdForTest(&systemd.Manager{
		UnitName: "sing-box.service", UnitPath: filepath.Join(dir, "sing-box.service"),
		BinaryPath: filepath.Join(dir, "sing-box"), ConfigPath: app.ConfigPath,
		RunCommand: func(context.Context, string, ...string) ([]byte, error) { return nil, nil },
	})
	svc.SetInstallerForTest(installStub(t, dir))
	if err := svc.Bootstrap(context.Background(), service.BootstrapOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapProdInstallProgress(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: false, ServerHost: "127.0.0.1",
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	fw := &trackingFirewall{}
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, fw, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SetRootCheckForTest(func() bool { return true })
	svc.SetSysctlForTest(&sysctl.Manager{ConfPath: filepath.Join(dir, "99-obscura.conf"), Reload: func() error { return nil }})
	svc.SetSystemdForTest(&systemd.Manager{
		UnitName: "sing-box.service", UnitPath: filepath.Join(dir, "sing-box.service"),
		BinaryPath: filepath.Join(dir, "sing-box"), ConfigPath: app.ConfigPath,
		RunCommand: func(context.Context, string, ...string) ([]byte, error) { return nil, nil },
	})
	var gotPercent int
	svc.SetInstallFnForTest(func(_ string, onDownload func(int64, int64)) (string, error) {
		if onDownload != nil {
			onDownload(55, 100)
		}
		return "1.0.0", nil
	})
	if err := svc.Bootstrap(context.Background(), service.BootstrapOptions{
		Progress: func(p service.BootstrapProgress) {
			if p.Percent > gotPercent {
				gotPercent = p.Percent
			}
		},
	}); err != nil {
		t.Fatal(err)
	}
	if gotPercent < 45 {
		t.Fatalf("install progress percent=%d, want >= 45", gotPercent)
	}
}

func TestEnableBootstrapFirewallUnavailable(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "m.json")}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, nil, singboxcheck.NopChecker{}, systemd.NopManager{})
	if err := svc.EnableBootstrapFirewall(context.Background(), service.BootstrapOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapWriteInitialConfigCheckFail(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: false, ServerHost: "127.0.0.1",
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, failChecker{}, systemd.NopManager{})
	svc.SetRootCheckForTest(func() bool { return true })
	svc.SetSysctlForTest(&sysctl.Manager{ConfPath: filepath.Join(dir, "sysctl.conf"), Reload: func() error { return nil }})
	svc.SetSystemdForTest(&systemd.Manager{
		UnitPath:   filepath.Join(dir, "sing-box.service"),
		RunCommand: func(context.Context, string, ...string) ([]byte, error) { return nil, nil },
	})
	svc.SetInstallerForTest(installStub(t, dir))
	err := svc.Bootstrap(context.Background(), service.BootstrapOptions{})
	if err == nil || !containsStr(err.Error(), "sing-box check initial config") {
		t.Fatalf("expected check error, got %v", err)
	}
}

func TestBootstrapRequiresRoot(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	if err := svc.Bootstrap(context.Background(), service.BootstrapOptions{}); err == nil {
		t.Fatal("expected root error")
	}
}

func installStub(t *testing.T, dir string) *install.Installer {
	t.Helper()
	inst := install.NewInstaller(filepath.Join(dir, "cache"))
	assets, err := install.LoadAssets()
	if err != nil {
		t.Fatal(err)
	}
	version := assets.Version
	inst.Stat = func(name string) (os.FileInfo, error) {
		if name == install.DefaultInstallPath {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}
	inst.RunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte(fmt.Sprintf("sing-box version %s\n", version)), nil
	}
	inst.ReportProgress = func(onDownload func(int64, int64)) {
		onDownload(55, 100)
	}
	return inst
}

func containsStr(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && stringIndex(s, sub) >= 0)
}

func stringIndex(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestEnableBootstrapFirewallError(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "m.json")}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, enableFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	if err := svc.EnableBootstrapFirewall(context.Background(), service.BootstrapOptions{}); err == nil {
		t.Fatal("expected firewall error")
	}
}

func TestBootstrapProdSysctlFail(t *testing.T) {
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
	svc.SetSysctlForTest(&sysctl.Manager{
		ConfPath: filepath.Join(dir, "sysctl.conf"),
		MkdirAll: func(string, os.FileMode) error { return fmt.Errorf("sysctl failed") },
	})
	if err := svc.Bootstrap(context.Background(), service.BootstrapOptions{}); err == nil {
		t.Fatal("expected sysctl error")
	}
}

func TestBootstrapWriteInitialConfigMkdirFail(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "block")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(blocker, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: true,
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	if err := svc.Bootstrap(context.Background(), service.BootstrapOptions{}); err == nil {
		t.Fatal("expected mkdir error")
	}
}

func TestBootstrapProdSystemdInstallFail(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: false, ServerHost: "127.0.0.1",
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SetRootCheckForTest(func() bool { return true })
	svc.SetSysctlForTest(&sysctl.Manager{ConfPath: filepath.Join(dir, "sysctl.conf"), Reload: func() error { return nil }})
	svc.SetSystemdForTest(&systemd.Manager{
		UnitPath: filepath.Join(dir, "sing-box.service"),
		RunCommand: func(context.Context, string, ...string) ([]byte, error) {
			return nil, fmt.Errorf("systemd failed")
		},
	})
	svc.SetInstallerForTest(installStub(t, dir))
	if err := svc.Bootstrap(context.Background(), service.BootstrapOptions{}); err == nil {
		t.Fatal("expected systemd install error")
	}
}

func TestBootstrapProdWithFallback(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: false, ServerHost: "127.0.0.1",
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	fw := &trackingFirewall{}
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, fw, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SetRootCheckForTest(func() bool { return true })
	svc.SetSysctlForTest(&sysctl.Manager{ConfPath: filepath.Join(dir, "99-obscura.conf"), Reload: func() error { return nil }})
	svc.SetSystemdForTest(&systemd.Manager{
		UnitName: "sing-box.service", UnitPath: filepath.Join(dir, "sing-box.service"),
		BinaryPath: filepath.Join(dir, "sing-box"), ConfigPath: app.ConfigPath,
		RunCommand: func(context.Context, string, ...string) ([]byte, error) { return nil, nil },
	})
	svc.SetInstallerForTest(installStub(t, dir))
	svc.SetFallbackInstallForTest(func(context.Context) error { return nil })
	if err := svc.Bootstrap(context.Background(), service.BootstrapOptions{WithFallbackStub: true}); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapProdInstallFail(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: false, ServerHost: "127.0.0.1",
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, &trackingFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SetRootCheckForTest(func() bool { return true })
	svc.SetSysctlForTest(&sysctl.Manager{ConfPath: filepath.Join(dir, "sysctl.conf"), Reload: func() error { return nil }})
	inst := install.NewInstaller(filepath.Join(dir, "cache"))
	inst.Stat = func(name string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	inst.RunCommand = func(string, ...string) ([]byte, error) { return nil, fmt.Errorf("download failed") }
	svc.SetInstallerForTest(inst)
	if err := svc.Bootstrap(context.Background(), service.BootstrapOptions{}); err == nil {
		t.Fatal("expected install error")
	}
}

func TestSyncSSHPortFromSystemWithManifestPort(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "m.json")}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	man.SetSSHPort(2222)
	_ = man.Save()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SyncSSHPortFromSystemForTest()
	if svc.SSHPort() != 2222 {
		t.Fatalf("port=%d", svc.SSHPort())
	}
}

func TestBootstrapProdRequiresRoot(t *testing.T) {
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
	if err := svc.Bootstrap(context.Background(), service.BootstrapOptions{}); err == nil {
		t.Fatal("expected root error")
	}
}

func TestBootstrapProdFirewallDuringBootstrap(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: false, ServerHost: "127.0.0.1",
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, enableFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SetRootCheckForTest(func() bool { return true })
	svc.SetSysctlForTest(&sysctl.Manager{ConfPath: filepath.Join(dir, "sysctl.conf"), Reload: func() error { return nil }})
	if err := svc.Bootstrap(context.Background(), service.BootstrapOptions{}); err == nil {
		t.Fatal("expected firewall error")
	}
}

func TestBootstrapRenderError(t *testing.T) {
	svc, st := newTestService(t)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := svc.Bootstrap(context.Background(), service.BootstrapOptions{}); err == nil {
		t.Fatal("expected render error")
	}
}

func TestWriteInitialConfigWriteFail(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: true,
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if err := svc.Bootstrap(context.Background(), service.BootstrapOptions{}); err == nil {
		t.Fatal("expected write error")
	}
}

func TestBootstrapProdStartFail(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: false, ServerHost: "127.0.0.1",
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, &trackingFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SetRootCheckForTest(func() bool { return true })
	svc.SetSysctlForTest(&sysctl.Manager{ConfPath: filepath.Join(dir, "sysctl.conf"), Reload: func() error { return nil }})
	svc.SetInstallerForTest(installStub(t, dir))
	svc.SetSystemdForTest(&systemd.Manager{
		UnitPath: filepath.Join(dir, "sing-box.service"),
		RunCommand: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "start" {
				return nil, fmt.Errorf("start failed")
			}
			return nil, nil
		},
	})
	if err := svc.Bootstrap(context.Background(), service.BootstrapOptions{}); err == nil {
		t.Fatal("expected start error")
	}
}

func TestBootstrapFallbackInstallFail(t *testing.T) {
	svc, _ := newTestService(t)
	svc.SetFallbackInstallForTest(func(context.Context) error { return fmt.Errorf("fallback failed") })
	if err := svc.Bootstrap(context.Background(), service.BootstrapOptions{WithFallbackStub: true}); err == nil {
		t.Fatal("expected fallback error")
	}
}

func TestBootstrapManifestSaveFail(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: true,
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	man.WriteFile = func(string, []byte, os.FileMode) error { return fmt.Errorf("save failed") }
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	if err := svc.Bootstrap(context.Background(), service.BootstrapOptions{}); err == nil {
		t.Fatal("expected manifest save error")
	}
}

func TestWriteInitialConfigRenderFail(t *testing.T) {
	svc, st := newTestService(t)
	fs := wrapFaultStore(st)
	fs.listEnabledVPNsErr = fmt.Errorf("render failed")
	svc.SetRendererForTest(render.NewRenderer(fs, runtime.NewProtocolRegistry()))
	if err := svc.WriteInitialConfigForTest(context.Background()); err == nil {
		t.Fatal("expected render error")
	}
}

func TestWriteInitialConfigProdCheckSuccess(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: false, ServerHost: "127.0.0.1",
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	checker := &checkRecorder{}
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, checker, systemd.NopManager{})
	if err := svc.WriteInitialConfigForTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !checker.called {
		t.Fatal("expected checker called")
	}
}

func TestWriteInitialConfigProdNoChecker(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: false, ServerHost: "127.0.0.1",
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, nil, systemd.NopManager{})
	if err := svc.WriteInitialConfigForTest(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestWriteInitialConfigWriteFileFail(t *testing.T) {
	svc, _ := newTestService(t)
	if err := os.Chmod(svc.DataDir(), 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(svc.DataDir(), 0o755) })
	if err := svc.WriteInitialConfigForTest(context.Background()); err == nil {
		t.Fatal("expected write error")
	}
}

func TestBootstrapFallbackManifestSaveFail(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: true,
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	saves := 0
	man.WriteFile = func(name string, data []byte, perm os.FileMode) error {
		saves++
		if saves >= 2 {
			return fmt.Errorf("save failed")
		}
		return os.WriteFile(name, data, perm)
	}
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SetFallbackInstallForTest(func(context.Context) error { return nil })
	if err := svc.Bootstrap(context.Background(), service.BootstrapOptions{WithFallbackStub: true}); err == nil {
		t.Fatal("expected fallback manifest save error")
	}
}
