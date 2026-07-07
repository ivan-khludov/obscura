package fallback_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/fallback"
)

func TestInstall_devMode(t *testing.T) {
	dir := t.TempDir()
	inst := fallback.Installer{DevMode: true, DataDir: dir}
	if err := inst.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(dir, "fallback")
	for _, path := range []string{
		filepath.Join(base, "Caddyfile"),
		filepath.Join(base, "site", "index.html"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
	}
	caddy, err := os.ReadFile(filepath.Join(base, "Caddyfile"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(caddy), fallback.DefaultServer+":8080") {
		t.Fatalf("unexpected caddyfile: %q", caddy)
	}
}

func TestInstall_devMode_mkdirFails(t *testing.T) {
	inst := fallback.Installer{
		DevMode: true,
		DataDir: t.TempDir(),
		MkdirAll: func(string, os.FileMode) error {
			return errors.New("mkdir failed")
		},
	}
	err := inst.Install(context.Background())
	if err == nil || !strings.Contains(err.Error(), "mkdir fallback") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstall_devMode_writeCaddyfileFails(t *testing.T) {
	inst := fallback.Installer{
		DevMode: true,
		DataDir: t.TempDir(),
		WriteFile: func(name string, _ []byte, _ os.FileMode) error {
			if strings.HasSuffix(name, "Caddyfile") {
				return errors.New("write failed")
			}
			return os.WriteFile(name, []byte("ok"), 0o644)
		},
	}
	err := inst.Install(context.Background())
	if err == nil || !strings.Contains(err.Error(), "write caddyfile") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstall_devMode_readEmbeddedFails(t *testing.T) {
	inst := fallback.Installer{
		DevMode: true,
		DataDir: t.TempDir(),
		ReadEmbedded: func(string) ([]byte, error) {
			return nil, errors.New("read failed")
		},
	}
	err := inst.Install(context.Background())
	if err == nil || !strings.Contains(err.Error(), "read embedded") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstall_prod_success(t *testing.T) {
	var calls []string
	inst := fallback.Installer{
		RunCommand: func(_ context.Context, name string, args ...string) ([]byte, error) {
			calls = append(calls, name+" "+strings.Join(args, " "))
			return []byte("ok\n"), nil
		},
		LookPath: func(file string) (string, error) {
			if file == "caddy" {
				return "/usr/bin/caddy", nil
			}
			return "", errors.New("not found")
		},
		MkdirAll:  func(string, os.FileMode) error { return nil },
		WriteFile: func(string, []byte, os.FileMode) error { return nil },
		ReadEmbedded: func(name string) ([]byte, error) {
			return []byte("unit"), nil
		},
	}
	if err := inst.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"systemctl daemon-reload",
		"systemctl enable " + fallback.UnitName,
		"systemctl start " + fallback.UnitName,
	}
	if len(calls) != len(want) {
		t.Fatalf("calls = %#v, want %#v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("call[%d] = %q, want %q", i, calls[i], want[i])
		}
	}
}

func TestInstall_prod_systemdMkdirFails(t *testing.T) {
	inst := fallback.Installer{
		MkdirAll: func(path string, _ os.FileMode) error {
			if path == filepath.Dir(fallback.UnitPath) {
				return errors.New("systemd mkdir failed")
			}
			return nil
		},
		WriteFile:    func(string, []byte, os.FileMode) error { return nil },
		ReadEmbedded: func(string) ([]byte, error) { return []byte("ok"), nil },
	}
	err := inst.Install(context.Background())
	if err == nil || !strings.Contains(err.Error(), "mkdir systemd") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstall_prod_copyEmbeddedWriteFails(t *testing.T) {
	inst := fallback.Installer{
		MkdirAll: func(string, os.FileMode) error { return nil },
		WriteFile: func(name string, _ []byte, _ os.FileMode) error {
			if name == fallback.UnitPath {
				return errors.New("write unit failed")
			}
			return nil
		},
		ReadEmbedded: func(string) ([]byte, error) { return []byte("unit"), nil },
	}
	err := inst.Install(context.Background())
	if err == nil || !strings.Contains(err.Error(), "write "+fallback.UnitPath) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstall_prod_ensureCaddy_noApt(t *testing.T) {
	inst := fallback.Installer{
		LookPath:     func(string) (string, error) { return "", errors.New("not found") },
		MkdirAll:     func(string, os.FileMode) error { return nil },
		WriteFile:    func(string, []byte, os.FileMode) error { return nil },
		ReadEmbedded: func(string) ([]byte, error) { return []byte("ok"), nil },
	}
	err := inst.Install(context.Background())
	if err == nil || !strings.Contains(err.Error(), "apt-get unavailable") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstall_prod_ensureCaddy_aptUpdateFails(t *testing.T) {
	inst := fallback.Installer{
		LookPath: func(file string) (string, error) {
			if file == "apt-get" {
				return "/usr/bin/apt-get", nil
			}
			return "", errors.New("not found")
		},
		RunCommand: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name == "apt-get" && args[0] == "update" {
				return []byte("update failed"), errors.New("update failed")
			}
			return nil, nil
		},
		MkdirAll:     func(string, os.FileMode) error { return nil },
		WriteFile:    func(string, []byte, os.FileMode) error { return nil },
		ReadEmbedded: func(string) ([]byte, error) { return []byte("ok"), nil },
	}
	err := inst.Install(context.Background())
	if err == nil || !strings.Contains(err.Error(), "apt-get update") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstall_prod_ensureCaddy_aptInstallFails(t *testing.T) {
	inst := fallback.Installer{
		LookPath: func(file string) (string, error) {
			if file == "apt-get" {
				return "/usr/bin/apt-get", nil
			}
			return "", errors.New("not found")
		},
		RunCommand: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name == "apt-get" && args[0] == "install" {
				return []byte("install failed"), errors.New("install failed")
			}
			return nil, nil
		},
		MkdirAll:     func(string, os.FileMode) error { return nil },
		WriteFile:    func(string, []byte, os.FileMode) error { return nil },
		ReadEmbedded: func(string) ([]byte, error) { return []byte("ok"), nil },
	}
	err := inst.Install(context.Background())
	if err == nil || !strings.Contains(err.Error(), "install caddy") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstall_prod_ensureCaddy_aptInstallSuccess(t *testing.T) {
	inst := fallback.Installer{
		LookPath: func(file string) (string, error) {
			if file == "apt-get" {
				return "/usr/bin/apt-get", nil
			}
			return "", errors.New("not found")
		},
		RunCommand: func(_ context.Context, name string, args ...string) ([]byte, error) {
			return nil, nil
		},
		MkdirAll:     func(string, os.FileMode) error { return nil },
		WriteFile:    func(string, []byte, os.FileMode) error { return nil },
		ReadEmbedded: func(string) ([]byte, error) { return []byte("ok"), nil },
	}
	if err := inst.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestInstall_prod_defaultLookPath(t *testing.T) {
	inst := fallback.Installer{
		MkdirAll:     func(string, os.FileMode) error { return nil },
		WriteFile:    func(string, []byte, os.FileMode) error { return nil },
		ReadEmbedded: func(string) ([]byte, error) { return []byte("ok"), nil },
	}
	if err := inst.Install(context.Background()); err == nil {
		t.Fatal("expected error from ensureCaddy with real lookPath")
	}
}

func TestInstall_prod_defaultRunCommand(t *testing.T) {
	inst := fallback.Installer{
		LookPath: func(file string) (string, error) {
			if file == "caddy" {
				return "/usr/bin/caddy", nil
			}
			return "", errors.New("not found")
		},
		MkdirAll:     func(string, os.FileMode) error { return nil },
		WriteFile:    func(string, []byte, os.FileMode) error { return nil },
		ReadEmbedded: func(string) ([]byte, error) { return []byte("ok"), nil },
	}
	if err := inst.Install(context.Background()); err == nil {
		t.Fatal("expected systemctl error with default runCommand")
	}
}

func TestInstall_copyEmbedded_mkdirUnitDirFails(t *testing.T) {
	unitDir := filepath.Dir(fallback.UnitPath)
	unitMkdirCalls := 0
	inst := fallback.Installer{
		MkdirAll: func(path string, _ os.FileMode) error {
			if path == unitDir {
				unitMkdirCalls++
				if unitMkdirCalls == 2 {
					return errors.New("copy embedded mkdir failed")
				}
			}
			return nil
		},
		WriteFile:    func(string, []byte, os.FileMode) error { return nil },
		ReadEmbedded: func(string) ([]byte, error) { return []byte("unit"), nil },
	}
	err := inst.Install(context.Background())
	if err == nil || !strings.Contains(err.Error(), "mkdir "+unitDir) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstall_prod_installUnitFails(t *testing.T) {
	inst := fallback.Installer{
		LookPath: func(file string) (string, error) {
			if file == "caddy" {
				return "/usr/bin/caddy", nil
			}
			return "", errors.New("not found")
		},
		RunCommand: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name == "systemctl" && args[0] == "daemon-reload" {
				return []byte("reload failed"), errors.New("reload failed")
			}
			return nil, nil
		},
		MkdirAll:     func(string, os.FileMode) error { return nil },
		WriteFile:    func(string, []byte, os.FileMode) error { return nil },
		ReadEmbedded: func(string) ([]byte, error) { return []byte("ok"), nil },
	}
	err := inst.Install(context.Background())
	if err == nil || !strings.Contains(err.Error(), "systemctl [daemon-reload]") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstall_prod_startFails(t *testing.T) {
	inst := fallback.Installer{
		LookPath: func(file string) (string, error) {
			if file == "caddy" {
				return "/usr/bin/caddy", nil
			}
			return "", errors.New("not found")
		},
		RunCommand: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name == "systemctl" && args[0] == "start" {
				return []byte("start failed"), errors.New("start failed")
			}
			return nil, nil
		},
		MkdirAll:     func(string, os.FileMode) error { return nil },
		WriteFile:    func(string, []byte, os.FileMode) error { return nil },
		ReadEmbedded: func(string) ([]byte, error) { return []byte("ok"), nil },
	}
	err := inst.Install(context.Background())
	if err == nil || !strings.Contains(err.Error(), "systemctl [start") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestActiveChecker_IsActive_true(t *testing.T) {
	c := fallback.ActiveChecker{
		RunCommand: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			return []byte("active\n"), nil
		},
	}
	active, err := c.IsActive(context.Background())
	if err != nil || !active {
		t.Fatalf("active=%v err=%v", active, err)
	}
}

func TestActiveChecker_IsActive_inactive(t *testing.T) {
	c := fallback.ActiveChecker{
		RunCommand: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			return []byte("inactive\n"), nil
		},
	}
	active, err := c.IsActive(context.Background())
	if err != nil || active {
		t.Fatalf("active=%v err=%v", active, err)
	}
}

func TestActiveChecker_IsActive_errorNoOutput(t *testing.T) {
	c := fallback.ActiveChecker{
		RunCommand: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			return nil, errors.New("systemctl missing")
		},
	}
	active, err := c.IsActive(context.Background())
	if err != nil || active {
		t.Fatalf("active=%v err=%v", active, err)
	}
}

func TestActiveChecker_IsActive_errorWithOutput(t *testing.T) {
	c := fallback.ActiveChecker{
		RunCommand: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			return []byte("failed\n"), errors.New("failed")
		},
	}
	active, err := c.IsActive(context.Background())
	if err != nil || active {
		t.Fatalf("active=%v err=%v", active, err)
	}
}

func TestIsActive(t *testing.T) {
	if _, err := fallback.IsActive(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestInstaller_installDir_production(t *testing.T) {
	wrote := make(map[string]struct{})
	inst := fallback.Installer{
		MkdirAll: func(path string, _ os.FileMode) error {
			wrote[path] = struct{}{}
			return nil
		},
		WriteFile:    func(string, []byte, os.FileMode) error { return nil },
		ReadEmbedded: func(string) ([]byte, error) { return []byte("ok"), nil },
		LookPath: func(file string) (string, error) {
			if file == "caddy" {
				return "/usr/bin/caddy", nil
			}
			return "", errors.New("not found")
		},
		RunCommand: func(context.Context, string, ...string) ([]byte, error) { return nil, nil },
	}
	if err := inst.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	siteDir := filepath.Join(fallback.InstallDir, "site")
	if _, ok := wrote[siteDir]; !ok {
		t.Fatalf("expected mkdir for production site dir %q, got %#v", siteDir, wrote)
	}
}
