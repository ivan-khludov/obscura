package service_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ivan-khludov/obscura/internal/config"
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/firewall"
	"github.com/ivan-khludov/obscura/internal/manifest"
	"github.com/ivan-khludov/obscura/internal/runtime"
	"github.com/ivan-khludov/obscura/internal/service"
	"github.com/ivan-khludov/obscura/internal/singboxcheck"
)

func TestRollbackConfig(t *testing.T) {
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
		Name: "first", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 12010},
	}); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(app.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "second", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 12011},
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(app.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(first) {
		t.Fatalf("rollback mismatch")
	}
	if err := svc.RollbackConfigForTest(ctx); err != nil {
		t.Fatal(err)
	}
}
