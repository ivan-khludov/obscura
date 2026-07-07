package systemd_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/systemd"
)

func testManager(t *testing.T, run func(context.Context, string, ...string) ([]byte, error)) *systemd.Manager {
	t.Helper()
	dir := t.TempDir()
	return &systemd.Manager{
		UnitName:   "sing-box.service",
		UnitPath:   filepath.Join(dir, "sing-box.service"),
		BinaryPath: "/usr/local/bin/sing-box",
		ConfigPath: "/etc/obscura/sing-box.json",
		RunCommand: run,
	}
}

func writeFakeSystemctl(t *testing.T, dir, script string) {
	t.Helper()
	path := filepath.Join(dir, "systemctl")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestNewManager(t *testing.T) {
	m := systemd.NewManager()
	if m.UnitName != systemd.DefaultUnitName ||
		m.UnitPath != systemd.DefaultUnitPath ||
		m.BinaryPath != systemd.DefaultBinaryPath ||
		m.ConfigPath != systemd.DefaultConfigPath {
		t.Fatalf("unexpected manager: %#v", m)
	}
}

func TestManager_InstallUnit_ok(t *testing.T) {
	var calls []string
	m := testManager(t, func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "systemctl" {
			t.Fatalf("command = %q", name)
		}
		calls = append(calls, strings.Join(args, " "))
		return nil, nil
	})
	if err := m.InstallUnit(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(m.UnitPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(raw)
	if !strings.Contains(content, m.BinaryPath) || !strings.Contains(content, m.ConfigPath) {
		t.Fatalf("unit content = %q", content)
	}
	if len(calls) != 2 || calls[0] != "daemon-reload" || calls[1] != "enable sing-box.service" {
		t.Fatalf("calls = %#v", calls)
	}
}

func TestManager_InstallUnit_mkdirError(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &systemd.Manager{
		UnitPath: filepath.Join(blocker, "nested", "sing-box.service"),
		RunCommand: func(context.Context, string, ...string) ([]byte, error) {
			return nil, nil
		},
	}
	err := m.InstallUnit(context.Background())
	if err == nil || !strings.Contains(err.Error(), "mkdir systemd") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestManager_InstallUnit_injectedMkdirError(t *testing.T) {
	m := testManager(t, func(context.Context, string, ...string) ([]byte, error) {
		return nil, nil
	})
	m.MkdirAll = func(string, os.FileMode) error {
		return errors.New("mkdir failed")
	}
	err := m.InstallUnit(context.Background())
	if err == nil || !strings.Contains(err.Error(), "mkdir systemd") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestManager_InstallUnit_writeError(t *testing.T) {
	m := testManager(t, func(context.Context, string, ...string) ([]byte, error) {
		return nil, nil
	})
	m.UnitPath = t.TempDir()
	err := m.InstallUnit(context.Background())
	if err == nil || !strings.Contains(err.Error(), "write unit") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestManager_InstallUnit_injectedWriteError(t *testing.T) {
	m := testManager(t, func(context.Context, string, ...string) ([]byte, error) {
		return nil, nil
	})
	m.WriteFile = func(string, []byte, os.FileMode) error {
		return errors.New("write failed")
	}
	err := m.InstallUnit(context.Background())
	if err == nil || !strings.Contains(err.Error(), "write unit") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestManager_InstallUnit_daemonReloadError(t *testing.T) {
	m := testManager(t, func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if args[0] == "daemon-reload" {
			return []byte("reload failed"), errors.New("exit status 1")
		}
		return nil, nil
	})
	err := m.InstallUnit(context.Background())
	if err == nil || !strings.Contains(err.Error(), "daemon-reload") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestManager_InstallUnit_enableError(t *testing.T) {
	m := testManager(t, func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if args[0] == "enable" {
			return []byte("enable failed"), errors.New("exit status 1")
		}
		return nil, nil
	})
	err := m.InstallUnit(context.Background())
	if err == nil || !strings.Contains(err.Error(), "enable sing-box.service") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestManager_StartStopReloadDisable(t *testing.T) {
	var calls []string
	m := testManager(t, func(_ context.Context, _ string, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		return nil, nil
	})
	ctx := context.Background()
	for _, fn := range []func(context.Context) error{m.Start, m.Stop, m.Reload, m.Disable} {
		if err := fn(ctx); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{
		"start sing-box.service",
		"stop sing-box.service",
		"restart sing-box.service",
		"disable sing-box.service",
	}
	if len(calls) != len(want) {
		t.Fatalf("calls = %#v", calls)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("calls[%d] = %q, want %q", i, calls[i], want[i])
		}
	}
}

func TestManager_run_error(t *testing.T) {
	m := testManager(t, func(context.Context, string, ...string) ([]byte, error) {
		return []byte("boom"), errors.New("exit status 1")
	})
	err := m.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestManager_defaultRunCommand(t *testing.T) {
	dir := t.TempDir()
	writeFakeSystemctl(t, dir, "#!/bin/sh\nexit 0\n")
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+oldPath)
	m := testManager(t, nil)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestManager_IsActive_active(t *testing.T) {
	m := testManager(t, func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if args[0] != "is-active" {
			t.Fatalf("args = %#v", args)
		}
		return []byte("active\n"), nil
	})
	active, err := m.IsActive(context.Background())
	if err != nil || !active {
		t.Fatalf("active = %v err=%v", active, err)
	}
}

func TestManager_IsActive_inactive(t *testing.T) {
	m := testManager(t, func(context.Context, string, ...string) ([]byte, error) {
		return []byte("inactive\n"), errors.New("exit status 3")
	})
	active, err := m.IsActive(context.Background())
	if err != nil || active {
		t.Fatalf("active = %v err=%v", active, err)
	}
}

func TestManager_IsActive_failedStatus(t *testing.T) {
	m := testManager(t, func(context.Context, string, ...string) ([]byte, error) {
		return []byte("failed\n"), errors.New("exit status 3")
	})
	active, err := m.IsActive(context.Background())
	if err == nil || err.Error() != "failed" || active {
		t.Fatalf("active = %v err=%v", active, err)
	}
}

func TestManager_IsActive_errorWithoutStatus(t *testing.T) {
	execErr := errors.New("command failed")
	m := testManager(t, func(context.Context, string, ...string) ([]byte, error) {
		return nil, execErr
	})
	active, err := m.IsActive(context.Background())
	if !errors.Is(err, execErr) || active {
		t.Fatalf("active = %v err=%v", active, err)
	}
}

func TestManager_IsActive_notActiveNoError(t *testing.T) {
	m := testManager(t, func(context.Context, string, ...string) ([]byte, error) {
		return []byte("unknown\n"), nil
	})
	active, err := m.IsActive(context.Background())
	if err != nil || active {
		t.Fatalf("active = %v err=%v", active, err)
	}
}

func TestManager_IsActive_defaultRunCommand(t *testing.T) {
	dir := t.TempDir()
	writeFakeSystemctl(t, dir, "#!/bin/sh\necho active\nexit 0\n")
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+oldPath)
	m := testManager(t, nil)
	active, err := m.IsActive(context.Background())
	if err != nil || !active {
		t.Fatalf("active = %v err=%v", active, err)
	}
}

func TestNopManager(t *testing.T) {
	var mgr systemd.NopManager
	if err := mgr.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	active, err := mgr.IsActive(context.Background())
	if err != nil || active {
		t.Fatalf("active = %v err=%v", active, err)
	}
}

func TestDefaults(t *testing.T) {
	if systemd.DefaultUnitName == "" || systemd.DefaultUnitPath == "" {
		t.Fatal("expected default unit constants")
	}
	if !strings.Contains(systemd.UnitTemplate, "ExecStart=%s run -c %s") {
		t.Fatal("unexpected unit template")
	}
}
