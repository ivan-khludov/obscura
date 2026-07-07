package sysctl_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/sysctl"
)

func writeFakeSysctl(t *testing.T, dir, script string) {
	t.Helper()
	path := filepath.Join(dir, "sysctl")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultEntries(t *testing.T) {
	entries := sysctl.DefaultEntries()
	if len(entries) != 3 {
		t.Fatalf("len = %d", len(entries))
	}
	var cc, qdisc string
	for _, e := range entries {
		switch e.Key {
		case sysctl.KeyCongestionControl:
			cc = e.Value
		case sysctl.KeyDefaultQdisc:
			qdisc = e.Value
		}
	}
	if cc != sysctl.DefaultCongestionControl {
		t.Fatalf("cc = %q", cc)
	}
	if qdisc != "fq" {
		t.Fatalf("qdisc = %q", qdisc)
	}
}

func TestEntries_emptyUsesDefault(t *testing.T) {
	entries := sysctl.Entries("  ")
	cc := entries[1].Value
	if cc != sysctl.DefaultCongestionControl {
		t.Fatalf("cc = %q", cc)
	}
}

func TestEntriesForAlgorithm(t *testing.T) {
	entries := sysctl.Entries("cubic")
	var cc, qdisc string
	for _, e := range entries {
		switch e.Key {
		case sysctl.KeyCongestionControl:
			cc = e.Value
		case sysctl.KeyDefaultQdisc:
			qdisc = e.Value
		}
	}
	if cc != "cubic" {
		t.Fatalf("expected cubic, got %q", cc)
	}
	if qdisc != "fq_codel" {
		t.Fatalf("expected fq_codel qdisc, got %q", qdisc)
	}
}

func TestDefaultQdiscFor(t *testing.T) {
	if got := sysctl.DefaultQdiscFor("bbr"); got != "fq" {
		t.Fatalf("bbr qdisc = %q", got)
	}
	if got := sysctl.DefaultQdiscFor("cubic"); got != "fq_codel" {
		t.Fatalf("cubic qdisc = %q", got)
	}
}

func TestValidateCongestionControl_ok(t *testing.T) {
	if err := sysctl.ValidateCongestionControl("bbr", []string{"cubic", "bbr"}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateCongestionControl_unsupported(t *testing.T) {
	err := sysctl.ValidateCongestionControl("vegas", []string{"cubic", "bbr"})
	if err == nil || !strings.Contains(err.Error(), "unsupported congestion control") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewManager(t *testing.T) {
	m := sysctl.NewManager()
	if m == nil || m.ConfPath != sysctl.DefaultConfPath {
		t.Fatalf("unexpected manager: %#v", m)
	}
}

func TestManagerApplyReload(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "99-obscura.conf")
	reloaded := false
	m := &sysctl.Manager{
		ConfPath: confPath,
		Reload: func() error {
			reloaded = true
			return nil
		},
	}
	if err := m.Apply(sysctl.DefaultEntries()); err != nil {
		t.Fatal(err)
	}
	if !reloaded {
		t.Fatal("expected reload to be called")
	}
	raw, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "net.ipv4.ip_forward") || !strings.Contains(string(raw), "bbr") {
		t.Fatalf("unexpected conf: %s", raw)
	}
}

func TestManagerApply_injectedMkdirError(t *testing.T) {
	m := &sysctl.Manager{
		ConfPath: filepath.Join(t.TempDir(), "99-obscura.conf"),
		MkdirAll: func(string, os.FileMode) error {
			return errors.New("mkdir failed")
		},
		Reload: func() error { return nil },
	}
	err := m.Apply(sysctl.DefaultEntries())
	if err == nil || !strings.Contains(err.Error(), "mkdir sysctl.d") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestManagerApply_injectedWriteError(t *testing.T) {
	m := &sysctl.Manager{
		ConfPath: filepath.Join(t.TempDir(), "99-obscura.conf"),
		WriteFile: func(string, []byte, os.FileMode) error {
			return errors.New("write failed")
		},
		Reload: func() error { return nil },
	}
	err := m.Apply(sysctl.DefaultEntries())
	if err == nil || !strings.Contains(err.Error(), "write sysctl conf") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestManagerApply_mkdirError(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &sysctl.Manager{
		ConfPath: filepath.Join(blocker, "nested", "99-obscura.conf"),
		Reload:   func() error { return nil },
	}
	err := m.Apply(sysctl.DefaultEntries())
	if err == nil || !strings.Contains(err.Error(), "mkdir sysctl.d") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestManagerApply_writeError(t *testing.T) {
	dir := t.TempDir()
	m := &sysctl.Manager{
		ConfPath: dir,
		Reload:   func() error { return nil },
	}
	err := m.Apply(sysctl.DefaultEntries())
	if err == nil || !strings.Contains(err.Error(), "write sysctl conf") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestManagerApply_reloadError(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "99-obscura.conf")
	m := &sysctl.Manager{
		ConfPath: confPath,
		Reload: func() error {
			return errors.New("reload failed")
		},
	}
	err := m.Apply(sysctl.DefaultEntries())
	if err == nil || !strings.Contains(err.Error(), "reload failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestManagerApply_defaultReload(t *testing.T) {
	dir := t.TempDir()
	writeFakeSysctl(t, dir, "#!/bin/sh\nexit 0\n")
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+oldPath)
	confPath := filepath.Join(t.TempDir(), "99-obscura.conf")
	m := &sysctl.Manager{ConfPath: confPath}
	if err := m.Apply(sysctl.DefaultEntries()); err != nil {
		t.Fatal(err)
	}
}

func TestManager_reloadSystemErrorWithOutput(t *testing.T) {
	dir := t.TempDir()
	writeFakeSysctl(t, dir, "#!/bin/sh\necho sysctl failed\nexit 1\n")
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+oldPath)
	m := &sysctl.Manager{ConfPath: filepath.Join(t.TempDir(), "99-obscura.conf")}
	if err := m.Apply(sysctl.DefaultEntries()); err == nil || !strings.Contains(err.Error(), "sysctl failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestManagerRemoveReload(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "99-obscura.conf")
	if err := os.WriteFile(confPath, []byte("net.ipv4.ip_forward = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	reloaded := false
	m := &sysctl.Manager{
		ConfPath: confPath,
		Reload: func() error {
			reloaded = true
			return nil
		},
	}
	if err := m.Remove(); err != nil {
		t.Fatal(err)
	}
	if !reloaded {
		t.Fatal("expected reload to be called")
	}
	if _, err := os.Stat(confPath); !os.IsNotExist(err) {
		t.Fatalf("expected conf removed, stat err=%v", err)
	}
}

func TestManagerRemove_missingFile(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "missing.conf")
	reloaded := false
	m := &sysctl.Manager{
		ConfPath: confPath,
		Reload: func() error {
			reloaded = true
			return nil
		},
	}
	if err := m.Remove(); err != nil {
		t.Fatal(err)
	}
	if !reloaded {
		t.Fatal("expected reload")
	}
}

func TestManagerRemove_error(t *testing.T) {
	m := &sysctl.Manager{
		ConfPath: "/etc/sysctl.d/99-obscura.conf",
		RemoveFile: func(string) error {
			return errors.New("remove failed")
		},
		Reload: func() error { return nil },
	}
	err := m.Remove()
	if err == nil || !strings.Contains(err.Error(), "remove sysctl conf") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestManagerRemove_reloadError(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "99-obscura.conf")
	if err := os.WriteFile(confPath, []byte("net.ipv4.ip_forward = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &sysctl.Manager{
		ConfPath: confPath,
		Reload: func() error {
			return errors.New("reload failed")
		},
	}
	err := m.Remove()
	if err == nil || !strings.Contains(err.Error(), "reload failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReader_ReadCurrent_ok(t *testing.T) {
	r := &sysctl.Reader{
		ReadFile: func(path string) ([]byte, error) {
			if !strings.HasSuffix(path, "/net/ipv4/tcp_congestion_control") {
				t.Fatalf("unexpected path: %s", path)
			}
			return []byte("bbr\n"), nil
		},
	}
	got, err := r.ReadCurrent(sysctl.KeyCongestionControl)
	if err != nil || got != "bbr" {
		t.Fatalf("ReadCurrent = %q err=%v", got, err)
	}
}

func TestReader_ReadCurrent_error(t *testing.T) {
	r := &sysctl.Reader{
		ReadFile: func(string) ([]byte, error) {
			return nil, errors.New("read failed")
		},
	}
	_, err := r.ReadCurrent(sysctl.KeyCongestionControl)
	if err == nil || !strings.Contains(err.Error(), "read net.ipv4.tcp_congestion_control") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadCurrent_defaultPath(t *testing.T) {
	path := "/proc/sys/net/ipv4/tcp_available_congestion_control"
	if _, err := os.Stat(path); err != nil {
		t.Skip("proc sysctl not available")
	}
	got, err := sysctl.ReadCurrent("net.ipv4.tcp_available_congestion_control")
	if err != nil || got == "" {
		t.Fatalf("ReadCurrent = %q err=%v", got, err)
	}
}

func TestReader_AvailableCongestionControls_ok(t *testing.T) {
	r := &sysctl.Reader{
		ReadFile: func(string) ([]byte, error) {
			return []byte("reno cubic bbr\n"), nil
		},
	}
	got, err := r.AvailableCongestionControls()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[2] != "bbr" {
		t.Fatalf("got %#v", got)
	}
}

func TestAvailableCongestionControls_packageFunc(t *testing.T) {
	path := "/proc/sys/net/ipv4/tcp_available_congestion_control"
	if _, err := os.Stat(path); err != nil {
		t.Skip("proc sysctl not available")
	}
	controls, err := sysctl.AvailableCongestionControls()
	if err != nil || len(controls) == 0 {
		t.Fatalf("AvailableCongestionControls = %#v err=%v", controls, err)
	}
}

func TestReader_AvailableCongestionControls_readError(t *testing.T) {
	r := &sysctl.Reader{
		ReadFile: func(string) ([]byte, error) {
			return nil, errors.New("read failed")
		},
	}
	_, err := r.AvailableCongestionControls()
	if err == nil || !strings.Contains(err.Error(), "read net.ipv4.tcp_available_congestion_control") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReader_AvailableCongestionControls_empty(t *testing.T) {
	r := &sysctl.Reader{
		ReadFile: func(string) ([]byte, error) {
			return []byte("   \n"), nil
		},
	}
	_, err := r.AvailableCongestionControls()
	if err == nil || !strings.Contains(err.Error(), "no congestion control algorithms reported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFallbackCongestionControls(t *testing.T) {
	if len(sysctl.FallbackCongestionControls) == 0 {
		t.Fatal("expected fallback controls")
	}
}
