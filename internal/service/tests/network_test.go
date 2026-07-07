package service_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ivan-khludov/obscura/internal/config"
	"github.com/ivan-khludov/obscura/internal/firewall"
	"github.com/ivan-khludov/obscura/internal/manifest"
	"github.com/ivan-khludov/obscura/internal/runtime"
	"github.com/ivan-khludov/obscura/internal/service"
	"github.com/ivan-khludov/obscura/internal/singboxcheck"
	"github.com/ivan-khludov/obscura/internal/sysctl"
	"github.com/ivan-khludov/obscura/internal/systemd"
)

func TestCongestionControlFromManifest(t *testing.T) {
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
	man.AddSysctl("net.ipv4.tcp_congestion_control", "cubic")
	_ = man.Save()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	if got := svc.CongestionControl(); got != "cubic" {
		t.Fatalf("expected cubic, got %q", got)
	}
}

func TestSetCongestionControlDevMode(t *testing.T) {
	svc, _ := newTestService(t)
	if err := svc.SetCongestionControl(context.Background(), "bbr"); err == nil {
		t.Fatal("expected dev mode error")
	}
}

func TestListCongestionControls(t *testing.T) {
	svc, _ := newTestService(t)
	list, err := svc.ListCongestionControls()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) == 0 {
		t.Fatal("expected congestion controls")
	}
}

func TestListCongestionControlsFallback(t *testing.T) {
	svc, _ := newTestService(t)
	svc.SetCongestionListerForTest(func() ([]string, error) {
		return nil, fmt.Errorf("unavailable")
	})
	list, err := svc.ListCongestionControls()
	if err != nil || len(list) == 0 {
		t.Fatalf("list=%v err=%v", list, err)
	}
}

func TestSetCongestionControlProd(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir:      dir,
		DBPath:       filepath.Join(dir, "state.db"),
		ConfigPath:   filepath.Join(dir, "sing-box.json"),
		ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode:      false,
		ServerHost:   "127.0.0.1",
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SetRootCheckForTest(func() bool { return true })
	svc.SetCongestionListerForTest(func() ([]string, error) { return []string{"bbr"}, nil })
	confPath := filepath.Join(dir, "99-obscura.conf")
	svc.SetSysctlForTest(&sysctl.Manager{
		ConfPath: confPath,
		Reload:   func() error { return nil },
	})
	if err := svc.SetCongestionControl(context.Background(), "bbr"); err != nil {
		t.Fatal(err)
	}
	if svc.CongestionControl() != "bbr" {
		t.Fatalf("expected bbr, got %q", svc.CongestionControl())
	}
}

func TestSetCongestionControlRequiresRoot(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir:      dir,
		DBPath:       filepath.Join(dir, "state.db"),
		ConfigPath:   filepath.Join(dir, "sing-box.json"),
		ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode:      false,
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SetRootCheckForTest(func() bool { return false })
	if err := svc.SetCongestionControl(context.Background(), "bbr"); err == nil {
		t.Fatal("expected root error")
	}
}

func TestSetCongestionControlInvalidAlgorithm(t *testing.T) {
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
	svc.SetCongestionListerForTest(func() ([]string, error) { return []string{"cubic"}, nil })
	if err := svc.SetCongestionControl(context.Background(), "bbr"); err == nil {
		t.Fatal("expected unsupported algorithm")
	}
}

func TestSetCongestionControlApplyFail(t *testing.T) {
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
	svc.SetCongestionListerForTest(func() ([]string, error) { return []string{"bbr"}, nil })
	svc.SetSysctlForTest(&sysctl.Manager{
		ConfPath: filepath.Join(dir, "sysctl.conf"),
		MkdirAll: func(string, os.FileMode) error { return fmt.Errorf("mkdir failed") },
	})
	if err := svc.SetCongestionControl(context.Background(), "bbr"); err == nil {
		t.Fatal("expected apply error")
	}
}

func TestSetCongestionControlListerFallback(t *testing.T) {
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
	svc.SetCongestionListerForTest(func() ([]string, error) { return nil, fmt.Errorf("unavailable") })
	svc.SetSysctlForTest(&sysctl.Manager{ConfPath: filepath.Join(dir, "sysctl.conf"), Reload: func() error { return nil }})
	if err := svc.SetCongestionControl(context.Background(), "bbr"); err != nil {
		t.Fatal(err)
	}
}

func TestSetCongestionControlManifestSaveFail(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: false,
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	man.WriteFile = func(string, []byte, os.FileMode) error { return fmt.Errorf("save failed") }
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SetRootCheckForTest(func() bool { return true })
	svc.SetCongestionListerForTest(func() ([]string, error) { return []string{"bbr"}, nil })
	svc.SetSysctlForTest(&sysctl.Manager{ConfPath: filepath.Join(dir, "sysctl.conf"), Reload: func() error { return nil }})
	if err := svc.SetCongestionControl(context.Background(), "bbr"); err == nil {
		t.Fatal("expected save error")
	}
}
