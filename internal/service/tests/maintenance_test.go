package service_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ivan-khludov/obscura/internal/backup"
	"github.com/ivan-khludov/obscura/internal/config"
	"github.com/ivan-khludov/obscura/internal/firewall"
	"github.com/ivan-khludov/obscura/internal/manifest"
	"github.com/ivan-khludov/obscura/internal/runtime"
	"github.com/ivan-khludov/obscura/internal/service"
	"github.com/ivan-khludov/obscura/internal/singboxcheck"
	"github.com/ivan-khludov/obscura/internal/sysctl"
	"github.com/ivan-khludov/obscura/internal/systemd"
)

func TestRestoreBackupCheckAndReload(t *testing.T) {
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
	checker := &checkRecorder{}
	reloader := &reloadRecorder{}
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, checker, reloader)
	ctx := context.Background()
	archive := filepath.Join(dir, "backup.tar.gz")
	if err := backup.Create(archive, []string{app.DBPath}); err != nil {
		t.Fatal(err)
	}
	if err := svc.RestoreBackup(ctx, archive); err != nil {
		t.Fatal(err)
	}
	if !checker.called {
		t.Fatal("expected sing-box check after restore")
	}
	if !reloader.called {
		t.Fatal("expected systemd reload after restore")
	}
}

// TestIsBootstrapped reports bootstrap state from manifest.
func TestListBackups(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	path, err := svc.CreateBackup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := svc.ListBackups(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Path != path {
		t.Fatalf("unexpected backups: %#v", entries)
	}
}

func TestUninstallFull(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir:      dir,
		DBPath:       filepath.Join(dir, "state.db"),
		ConfigPath:   filepath.Join(dir, "sing-box.json"),
		ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode:      true,
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	man.AddFirewallRule("1080/tcp")
	_ = man.Save()
	fw := &trackingFirewall{}
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, fw, singboxcheck.NopChecker{}, systemd.NopManager{})
	confPath := filepath.Join(dir, "99-obscura.conf")
	svc.SetSysctlForTest(&sysctl.Manager{ConfPath: confPath, Reload: func() error { return nil }})
	ctx := context.Background()
	if err := svc.UninstallFull(ctx, false); err != nil {
		t.Fatal(err)
	}
	if err := svc.UninstallFullForTest(ctx, true); err != nil {
		t.Fatal(err)
	}
}

func TestListBackupsSkipsMissingStat(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	backupDir := filepath.Join(svc.DataDir(), "backups")
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, "broken.tar.gz"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := svc.ListBackups(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = entries
}

func TestRestoreBackupWithoutCheckAndReload(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, nil, nil)
	archive := filepath.Join(dir, "backup.tar.gz")
	if err := backup.Create(archive, []string{app.DBPath}); err != nil {
		t.Fatal(err)
	}
	if err := svc.RestoreBackup(context.Background(), archive); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreBackupCheckFail(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, failChecker{}, systemd.NopManager{})
	archive := filepath.Join(dir, "backup.tar.gz")
	if err := backup.Create(archive, []string{app.DBPath}); err != nil {
		t.Fatal(err)
	}
	if err := svc.RestoreBackup(context.Background(), archive); err == nil {
		t.Fatal("expected check failure")
	}
}

func TestUninstallFullWithPlan(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "manifest.json")}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	man.AddService("sing-box.service")
	man.AddFile(filepath.Join(dir, "extra.txt"), false)
	man.AddBinary(filepath.Join(dir, "bin"))
	_ = man.Save()
	_ = os.WriteFile(filepath.Join(dir, "extra.txt"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "bin"), []byte("x"), 0o755)
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, &trackingFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SetSysctlForTest(&sysctl.Manager{ConfPath: filepath.Join(dir, "sysctl.conf"), Reload: func() error { return nil }, RemoveFile: os.Remove})
	if err := svc.UninstallFull(context.Background(), false); err != nil {
		t.Fatal(err)
	}
}

func TestCreateBackupMkdirFail(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "block")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	app := &config.App{
		DataDir: filepath.Join(blocker, "data"), DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	if _, err := svc.CreateBackup(context.Background()); err == nil {
		t.Fatal("expected mkdir error")
	}
}

func TestRestoreBackupReloadFail(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, &reloadFail{})
	archive := filepath.Join(dir, "backup.tar.gz")
	if err := backup.Create(archive, []string{app.DBPath}); err != nil {
		t.Fatal(err)
	}
	if err := svc.RestoreBackup(context.Background(), archive); err == nil {
		t.Fatal("expected reload error")
	}
}

type reloadFail struct{}

func (reloadFail) Reload(_ context.Context) error           { return fmt.Errorf("reload failed") }
func (reloadFail) IsActive(_ context.Context) (bool, error) { return false, nil }

func TestRestoreBackupExtractFail(t *testing.T) {
	svc, _ := newTestService(t)
	if err := svc.RestoreBackup(context.Background(), filepath.Join(svc.DataDir(), "missing.tar.gz")); err == nil {
		t.Fatal("expected restore error")
	}
}

func TestUninstallSysctlFail(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "manifest.json")}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SetSysctlForTest(&sysctl.Manager{
		ConfPath:   filepath.Join(dir, "sysctl.conf"),
		RemoveFile: func(string) error { return fmt.Errorf("remove failed") },
	})
	if err := svc.UninstallFull(context.Background(), false); err == nil {
		t.Fatal("expected sysctl error")
	}
}

func TestListBackupsGlobError(t *testing.T) {
	svc, _ := newTestService(t)
	svc.SetBackupGlobForTest(func(string) ([]string, error) {
		return nil, fmt.Errorf("glob failed")
	})
	if _, err := svc.ListBackups(context.Background()); err == nil {
		t.Fatal("expected glob error")
	}
}

func TestListBackupsSorted(t *testing.T) {
	svc, _ := newTestService(t)
	svc.SetBackupGlobForTest(func(string) ([]string, error) {
		return []string{
			filepath.Join(svc.DataDir(), "backups", "old.tar.gz"),
			filepath.Join(svc.DataDir(), "backups", "new.tar.gz"),
		}, nil
	})
	dir := filepath.Join(svc.DataDir(), "backups")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	oldPath := filepath.Join(dir, "old.tar.gz")
	newPath := filepath.Join(dir, "new.tar.gz")
	if err := os.WriteFile(oldPath, []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(oldPath, time.Now().Add(-time.Hour), time.Now().Add(-time.Hour))
	entries, err := svc.ListBackups(context.Background())
	if err != nil || len(entries) != 2 || entries[0].Name != "new.tar.gz" {
		t.Fatalf("entries=%#v err=%v", entries, err)
	}
}

func TestCreateBackupUnreadableSource(t *testing.T) {
	svc, _ := newTestService(t)
	dbPath := filepath.Join(svc.DataDir(), "state.db")
	if err := os.Chmod(dbPath, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dbPath, 0o644) })
	if _, err := svc.CreateBackup(context.Background()); err == nil {
		t.Fatal("expected backup create error")
	}
}

func TestListBackupsSkipMissingStat(t *testing.T) {
	svc, _ := newTestService(t)
	missing := filepath.Join(svc.DataDir(), "backups", "gone.tar.gz")
	svc.SetBackupGlobForTest(func(string) ([]string, error) {
		return []string{missing}, nil
	})
	entries, err := svc.ListBackups(context.Background())
	if err != nil || len(entries) != 0 {
		t.Fatalf("entries=%#v err=%v", entries, err)
	}
}

func TestUninstallFullStopServices(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "manifest.json")}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	man.AddService("sing-box.service")
	_ = man.Save()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SetSysctlForTest(&sysctl.Manager{ConfPath: filepath.Join(dir, "sysctl.conf"), Reload: func() error { return nil }, RemoveFile: os.Remove})
	if err := svc.UninstallFull(context.Background(), false); err != nil {
		t.Fatal(err)
	}
}

func TestUninstallFullRemoveFiles(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "manifest.json")}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	extra := filepath.Join(dir, "extra.txt")
	man.AddFile(extra, true)
	_ = man.Save()
	_ = os.WriteFile(extra, []byte("x"), 0o644)
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SetSysctlForTest(&sysctl.Manager{ConfPath: filepath.Join(dir, "sysctl.conf"), Reload: func() error { return nil }, RemoveFile: os.Remove})
	if err := svc.UninstallFull(context.Background(), false); err != nil {
		t.Fatal(err)
	}
}
