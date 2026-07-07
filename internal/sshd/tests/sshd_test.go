package sshd_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/sshd"
)

func TestValidatePort(t *testing.T) {
	if err := sshd.ValidatePort(22); err != nil {
		t.Fatal(err)
	}
	if err := sshd.ValidatePort(65535); err != nil {
		t.Fatal(err)
	}
	if err := sshd.ValidatePort(0); err == nil {
		t.Fatal("expected error for port 0")
	}
	if err := sshd.ValidatePort(65536); err == nil {
		t.Fatal("expected error for port 65536")
	}
}

func TestReadPort_missingFile(t *testing.T) {
	port, err := sshd.ReadPort(filepath.Join(t.TempDir(), "missing.conf"))
	if err != nil || port != sshd.DefaultPort {
		t.Fatalf("got port=%d err=%v", port, err)
	}
}

func TestReadPort_readError(t *testing.T) {
	dir := t.TempDir()
	port, err := sshd.ReadPort(dir)
	if err == nil || !strings.Contains(err.Error(), "read sshd config") {
		t.Fatalf("unexpected error: %v", err)
	}
	if port != 0 {
		t.Fatalf("port = %d, want 0", port)
	}
}

func TestReadPort_defaultFromComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(path, []byte("# comment\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	port, err := sshd.ReadPort(path)
	if err != nil || port != sshd.DefaultPort {
		t.Fatalf("got port=%d err=%v", port, err)
	}
}

func TestReadPort_explicit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	content := "# old\nPort 2222\nInclude /etc/ssh/sshd_config.d/*.conf\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	port, err := sshd.ReadPort(path)
	if err != nil || port != 2222 {
		t.Fatalf("got port=%d err=%v", port, err)
	}
}

func TestReadPort_caseInsensitive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(path, []byte("pOrT 8022\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	port, err := sshd.ReadPort(path)
	if err != nil || port != 8022 {
		t.Fatalf("got port=%d err=%v", port, err)
	}
}

func TestReadPort_invalidDirective(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(path, []byte("Port abc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := sshd.ReadPort(path)
	if err == nil || !strings.Contains(err.Error(), "invalid Port directive") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadPort_invalidPortRange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(path, []byte("Port 70000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := sshd.ReadPort(path)
	if err == nil || !strings.Contains(err.Error(), "65535") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfig_ReadPort_injectedReadError(t *testing.T) {
	c := &sshd.Config{
		ReadFile: func(string) ([]byte, error) {
			return nil, errors.New("read failed")
		},
	}
	_, err := c.ReadPort("/tmp/sshd_config")
	if err == nil || !strings.Contains(err.Error(), "read sshd config") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetPort_replaceExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(path, []byte("Port 22\nPermitRootLogin no\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := sshd.SetPort(path, 2222); err != nil {
		t.Fatal(err)
	}
	port, err := sshd.ReadPort(path)
	if err != nil || port != 2222 {
		t.Fatalf("after replace: got port=%d err=%v", port, err)
	}
	raw, err := os.ReadFile(path + ".obscura.bak")
	if err != nil || string(raw) != "Port 22\nPermitRootLogin no\n" {
		t.Fatalf("backup = %q err=%v", raw, err)
	}
}

func TestSetPort_addWhenMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.conf")
	if err := os.WriteFile(path, []byte("PermitRootLogin no\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := sshd.SetPort(path, 8022); err != nil {
		t.Fatal(err)
	}
	port, err := sshd.ReadPort(path)
	if err != nil || port != 8022 {
		t.Fatalf("after add: got port=%d err=%v", port, err)
	}
}

func TestSetPort_addWithoutTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(path, []byte("PermitRootLogin no"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := sshd.SetPort(path, 8022); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "Port 8022") {
		t.Fatalf("config = %q", raw)
	}
}

func TestSetPort_invalidPort(t *testing.T) {
	err := sshd.SetPort(filepath.Join(t.TempDir(), "sshd_config"), 0)
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestSetPort_readError(t *testing.T) {
	dir := t.TempDir()
	err := sshd.SetPort(dir, 2222)
	if err == nil || !strings.Contains(err.Error(), "read sshd config") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetPort_backupError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(path, []byte("Port 22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	err := sshd.SetPort(path, 2222)
	if err == nil || !strings.Contains(err.Error(), "backup sshd config") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfig_SetPort_writeErrorRollback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	original := []byte("Port 22\n")
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}
	writes := 0
	c := &sshd.Config{
		ReadFile: os.ReadFile,
		WriteFile: func(name string, data []byte, perm os.FileMode) error {
			writes++
			if writes == 2 && name == path {
				return errors.New("write failed")
			}
			return os.WriteFile(name, data, perm)
		},
	}
	err := c.SetPort(path, 2222)
	if err == nil || !strings.Contains(err.Error(), "write sshd config") {
		t.Fatalf("unexpected error: %v", err)
	}
	raw, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(raw) != string(original) {
		t.Fatalf("rollback failed: got %q", raw)
	}
}

func TestRestoreBackup_ok(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	backup := path + ".obscura.bak"
	if err := os.WriteFile(backup, []byte("Port 22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := sshd.RestoreBackup(path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "Port 22\n" {
		t.Fatalf("restored = %q err=%v", raw, err)
	}
}

func TestRestoreBackup_missing(t *testing.T) {
	err := sshd.RestoreBackup(filepath.Join(t.TempDir(), "sshd_config"))
	if err == nil {
		t.Fatal("expected error for missing backup")
	}
}

func TestConfigDir(t *testing.T) {
	if got := sshd.ConfigDir(""); got != filepath.Dir(sshd.ConfigPath) {
		t.Fatalf("ConfigDir(\"\") = %q", got)
	}
	if got := sshd.ConfigDir("/etc/ssh/custom.conf"); got != "/etc/ssh" {
		t.Fatalf("ConfigDir(custom) = %q", got)
	}
}

func TestRunner_TestConfig_ok(t *testing.T) {
	r := &sshd.Runner{
		RunCommand: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name != "sshd" || len(args) != 3 || args[0] != "-t" || args[1] != "-f" || args[2] != "/tmp/sshd.conf" {
				t.Fatalf("unexpected command: %s %v", name, args)
			}
			return nil, nil
		},
	}
	if err := r.TestConfig(context.Background(), "/tmp/sshd.conf"); err != nil {
		t.Fatal(err)
	}
}

func TestRunner_TestConfig_defaultPath(t *testing.T) {
	var path string
	r := &sshd.Runner{
		RunCommand: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			path = args[2]
			return nil, nil
		},
	}
	if err := r.TestConfig(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if path != sshd.ConfigPath {
		t.Fatalf("path = %q, want %q", path, sshd.ConfigPath)
	}
}

func TestRunner_TestConfig_error(t *testing.T) {
	execErr := errors.New("exit status 255")
	r := &sshd.Runner{
		RunCommand: func(context.Context, string, ...string) ([]byte, error) {
			return []byte("bad config\n"), execErr
		},
	}
	err := r.TestConfig(context.Background(), "/tmp/sshd.conf")
	if err == nil || !strings.Contains(err.Error(), "bad config") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func writeFakeCommand(t *testing.T, dir, name, script string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunner_TestConfig_defaultRunCommand(t *testing.T) {
	dir := t.TempDir()
	writeFakeCommand(t, dir, "sshd", "#!/bin/sh\nexit 0\n")
	config := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(config, []byte("Port 22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+oldPath)
	if err := (&sshd.Runner{}).TestConfig(context.Background(), config); err != nil {
		t.Fatal(err)
	}
}

func TestRunner_Reload_firstUnitOk(t *testing.T) {
	r := &sshd.Runner{
		RunCommand: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name == "systemctl" && len(args) == 2 && args[0] == "reload" && args[1] == "ssh" {
				return nil, nil
			}
			return nil, errors.New("unexpected")
		},
	}
	if err := r.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRunner_Reload_secondUnitOk(t *testing.T) {
	calls := 0
	r := &sshd.Runner{
		RunCommand: func(_ context.Context, name string, args ...string) ([]byte, error) {
			calls++
			if name != "systemctl" || args[0] != "reload" {
				t.Fatalf("unexpected command: %s %v", name, args)
			}
			if args[1] == "ssh" {
				return []byte("not found"), errors.New("exit status 5")
			}
			if args[1] == "sshd" {
				return nil, nil
			}
			return nil, errors.New("unexpected unit")
		},
	}
	if err := r.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
}

func TestRunner_Reload_allFail(t *testing.T) {
	r := &sshd.Runner{
		RunCommand: func(context.Context, string, ...string) ([]byte, error) {
			return []byte("failed"), errors.New("exit status 1")
		},
	}
	err := r.Reload(context.Background())
	if err == nil || !strings.Contains(err.Error(), "systemctl reload sshd") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunner_Reload_noUnits(t *testing.T) {
	r := &sshd.Runner{ReloadUnits: []string{}}
	err := r.Reload(context.Background())
	if err == nil || !strings.Contains(err.Error(), "ssh service not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReload_defaultRunCommand(t *testing.T) {
	dir := t.TempDir()
	writeFakeCommand(t, dir, "systemctl", "#!/bin/sh\nexit 0\n")
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+oldPath)
	if err := sshd.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
}

func TestTestConfig_packageFunc(t *testing.T) {
	dir := t.TempDir()
	writeFakeCommand(t, dir, "sshd", "#!/bin/sh\nexit 0\n")
	config := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(config, []byte("Port 22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+oldPath)
	if err := sshd.TestConfig(context.Background(), config); err != nil {
		t.Fatalf("TestConfig: %v", err)
	}
}

func TestKeepalive_Content(t *testing.T) {
	k := sshd.NewKeepalive()
	want := "ClientAliveInterval 15\nClientAliveCountMax 6\n"
	if got := k.Content(); got != want {
		t.Fatalf("Content() = %q, want %q", got, want)
	}
	var nilKeepalive *sshd.Keepalive
	if got := nilKeepalive.Content(); got != want {
		t.Fatalf("nil Content() = %q, want %q", got, want)
	}
}

func TestKeepalive_Install(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "sshd_config.d", "99-obscura.conf")
	reloaded := false
	k := &sshd.Keepalive{
		ConfPath: confPath,
		Config:   &sshd.Config{ReadFile: os.ReadFile, WriteFile: os.WriteFile},
		Runner: &sshd.Runner{
			RunCommand: func(_ context.Context, name string, args ...string) ([]byte, error) {
				if name == "sshd" && len(args) >= 1 && args[0] == "-t" {
					return nil, nil
				}
				if name == "systemctl" && len(args) == 2 && args[0] == "reload" {
					reloaded = true
					return nil, nil
				}
				return nil, errors.New("unexpected command")
			},
		},
	}
	if err := k.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != k.Content() {
		t.Fatalf("conf = %q", raw)
	}
	if !reloaded {
		t.Fatal("expected ssh reload")
	}
}

func TestKeepalive_InstallTestConfigFail(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "sshd_config.d", "99-obscura.conf")
	k := &sshd.Keepalive{
		ConfPath: confPath,
		Config:   &sshd.Config{ReadFile: os.ReadFile, WriteFile: os.WriteFile},
		Runner: &sshd.Runner{
			RunCommand: func(context.Context, string, ...string) ([]byte, error) {
				return []byte("bad"), errors.New("sshd -t failed")
			},
		},
	}
	err := k.Install(context.Background())
	if err == nil || !strings.Contains(err.Error(), "sshd test after keepalive install") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(confPath); !os.IsNotExist(statErr) {
		t.Fatalf("expected conf removed on failure, err=%v", statErr)
	}
}

func TestKeepalive_Remove(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "sshd_config.d", "99-obscura.conf")
	if err := os.MkdirAll(filepath.Dir(confPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(confPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	reloaded := false
	k := &sshd.Keepalive{
		ConfPath: confPath,
		Runner: &sshd.Runner{
			RunCommand: func(_ context.Context, name string, args ...string) ([]byte, error) {
				if name == "systemctl" && len(args) == 2 && args[0] == "reload" {
					reloaded = true
					return nil, nil
				}
				return nil, errors.New("unexpected")
			},
		},
	}
	if err := k.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(confPath); !os.IsNotExist(err) {
		t.Fatalf("expected conf removed, err=%v", err)
	}
	if !reloaded {
		t.Fatal("expected ssh reload")
	}
}

func TestKeepalive_InstallMkdirFail(t *testing.T) {
	k := &sshd.Keepalive{
		ConfPath: filepath.Join(t.TempDir(), "blocked", "99-obscura.conf"),
		MkdirAll: func(string, os.FileMode) error { return errors.New("mkdir failed") },
	}
	err := k.Install(context.Background())
	if err == nil || !strings.Contains(err.Error(), "mkdir sshd_config.d") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestKeepalive_InstallReloadFail(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "sshd_config.d", "99-obscura.conf")
	k := &sshd.Keepalive{
		ConfPath: confPath,
		Config:   &sshd.Config{ReadFile: os.ReadFile, WriteFile: os.WriteFile},
		Runner: &sshd.Runner{
			RunCommand: func(_ context.Context, name string, args ...string) ([]byte, error) {
				if name == "sshd" {
					return nil, nil
				}
				return []byte("reload failed"), errors.New("reload failed")
			},
		},
	}
	err := k.Install(context.Background())
	if err == nil || !strings.Contains(err.Error(), "reload ssh after keepalive install") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(confPath); !os.IsNotExist(statErr) {
		t.Fatalf("expected conf removed on reload failure, err=%v", statErr)
	}
}

func TestKeepalive_RemoveMissing(t *testing.T) {
	reloaded := false
	k := &sshd.Keepalive{
		ConfPath: filepath.Join(t.TempDir(), "missing.conf"),
		Runner: &sshd.Runner{
			RunCommand: func(context.Context, string, ...string) ([]byte, error) {
				reloaded = true
				return nil, nil
			},
		},
	}
	if err := k.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	if reloaded {
		t.Fatal("expected no reload when keepalive file is absent")
	}
}

func TestKeepalive_RemoveStatError(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "locked")
	if err := os.Mkdir(parent, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })
	k := &sshd.Keepalive{ConfPath: filepath.Join(parent, "99-obscura.conf")}
	err := k.Remove(context.Background())
	if err == nil || !strings.Contains(err.Error(), "stat ssh keepalive conf") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstalled(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "sshd")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if !sshd.Installed() {
		t.Fatal("expected sshd in PATH to be detected")
	}
}
