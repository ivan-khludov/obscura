package singboxcheck_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ivan-khludov/obscura/internal/singboxcheck"
)

type stubFileInfo struct{}

func (stubFileInfo) Name() string       { return "sing-box" }
func (stubFileInfo) Size() int64        { return 0 }
func (stubFileInfo) Mode() fs.FileMode  { return 0o755 }
func (stubFileInfo) ModTime() time.Time { return time.Time{} }
func (stubFileInfo) IsDir() bool        { return false }
func (stubFileInfo) Sys() any           { return nil }

func statOK(string) (fs.FileInfo, error) {
	return stubFileInfo{}, nil
}

func TestNewChecker(t *testing.T) {
	if got := singboxcheck.NewChecker("").BinaryPath; got != singboxcheck.DefaultBinaryPath {
		t.Fatalf("default path = %q, want %q", got, singboxcheck.DefaultBinaryPath)
	}
	if got := singboxcheck.NewChecker("/opt/sing-box").BinaryPath; got != "/opt/sing-box" {
		t.Fatalf("custom path = %q", got)
	}
}

func TestChecker_Check_MissingBinary(t *testing.T) {
	dir := t.TempDir()
	c := singboxcheck.NewChecker(filepath.Join(dir, "missing-sing-box"))
	err := c.Check(context.Background(), filepath.Join(dir, "config.json"))
	if err == nil {
		t.Fatal("expected error for missing binary")
	}
	if !strings.Contains(err.Error(), "Bootstrap server first") {
		t.Fatalf("expected bootstrap hint: %v", err)
	}
}

func TestChecker_Check_StatError(t *testing.T) {
	c := singboxcheck.NewChecker("/usr/local/bin/sing-box")
	c.Stat = func(string) (fs.FileInfo, error) {
		return nil, errors.New("permission denied")
	}
	err := c.Check(context.Background(), "/tmp/config.json")
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestChecker_Check_Success(t *testing.T) {
	c := singboxcheck.NewChecker("/usr/local/bin/sing-box")
	c.Stat = statOK
	c.RunCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "/usr/local/bin/sing-box" || len(args) != 3 || args[0] != "check" || args[1] != "-c" || args[2] != "/tmp/config.json" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return []byte("ok\n"), nil
	}
	if err := c.Check(context.Background(), "/tmp/config.json"); err != nil {
		t.Fatalf("Check: %v", err)
	}
}

func TestChecker_Check_ExecErrorWithOutput(t *testing.T) {
	c := singboxcheck.NewChecker("/usr/local/bin/sing-box")
	c.Stat = statOK
	execErr := errors.New("exit status 1")
	c.RunCommand = func(context.Context, string, ...string) ([]byte, error) {
		return []byte("invalid config\n"), execErr
	}
	err := c.Check(context.Background(), "/tmp/config.json")
	if err == nil || !strings.Contains(err.Error(), "invalid config") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestChecker_Check_ExecErrorWithoutOutput(t *testing.T) {
	c := singboxcheck.NewChecker("/usr/local/bin/sing-box")
	c.Stat = statOK
	execErr := errors.New("signal killed")
	c.RunCommand = func(context.Context, string, ...string) ([]byte, error) {
		return nil, execErr
	}
	if err := c.Check(context.Background(), "/tmp/config.json"); !errors.Is(err, execErr) {
		t.Fatalf("expected exec error, got %v", err)
	}
}

func TestNopChecker_Check(t *testing.T) {
	var checker singboxcheck.NopChecker
	if err := checker.Check(context.Background(), "/tmp/config.json"); err != nil {
		t.Fatalf("NopChecker.Check: %v", err)
	}
}

func TestDefaultBinaryPath(t *testing.T) {
	if singboxcheck.DefaultBinaryPath == "" {
		t.Fatal("expected non-empty default binary path")
	}
}

func writeFakeSingBox(t *testing.T, dir, script string) string {
	t.Helper()
	path := filepath.Join(dir, "sing-box")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestChecker_Check_defaultRunCommand(t *testing.T) {
	dir := t.TempDir()
	binary := writeFakeSingBox(t, dir, "#!/bin/sh\nexit 0\n")
	config := filepath.Join(dir, "config.json")
	if err := os.WriteFile(config, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := singboxcheck.NewChecker(binary)
	if err := c.Check(context.Background(), config); err != nil {
		t.Fatalf("Check: %v", err)
	}
}

func TestChecker_Check_defaultRunCommandErrorWithOutput(t *testing.T) {
	dir := t.TempDir()
	binary := writeFakeSingBox(t, dir, "#!/bin/sh\necho invalid config\nexit 1\n")
	config := filepath.Join(dir, "config.json")
	if err := os.WriteFile(config, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := singboxcheck.NewChecker(binary)
	err := c.Check(context.Background(), config)
	if err == nil || !strings.Contains(err.Error(), "invalid config") {
		t.Fatalf("unexpected error: %v", err)
	}
}
