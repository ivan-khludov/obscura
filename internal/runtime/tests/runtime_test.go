package runtime_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/ivan-khludov/obscura/internal/config"
	"github.com/ivan-khludov/obscura/internal/manifest"
	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/runtime"
	"github.com/ivan-khludov/obscura/internal/store"
)

func testRoot() *cobra.Command {
	root := &cobra.Command{Use: "obscura"}
	root.AddCommand(&cobra.Command{Use: "vpn"})
	root.AddCommand(&cobra.Command{Use: "bootstrap"})
	return root
}

func tempApp(dir string, devMode bool) *config.App {
	return &config.App{
		DataDir:      dir,
		DBPath:       filepath.Join(dir, "state.db"),
		ConfigPath:   filepath.Join(dir, "sing-box.json"),
		ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode:      devMode,
		ServerHost:   "example.com",
	}
}

func TestShouldRunTUI(t *testing.T) {
	root := testRoot()
	tests := []struct {
		name string
		root *cobra.Command
		args []string
		want bool
	}{
		{"empty", root, nil, true},
		{"dev flag only", root, []string{"--dev"}, true},
		{"json flag only", root, []string{"--json"}, true},
		{"vpn subcommand", root, []string{"vpn", "list"}, false},
		{"bootstrap", root, []string{"bootstrap"}, false},
		{"help is subcommand", root, []string{"help"}, false},
		{"nil root empty args", nil, nil, true},
		{"nil root with args", nil, []string{"vpn"}, false},
		{"find error", root, []string{"nonexistent-cmd"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := runtime.ShouldRunTUI(tc.root, tc.args); got != tc.want {
				t.Fatalf("ShouldRunTUI(%v) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

func TestOpen_devMode(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	svc, app, cleanup, err := runtime.Open(true)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	if cleanup == nil || svc == nil || app == nil {
		t.Fatalf("svc=%v app=%v cleanup nil=%v", svc, app, cleanup == nil)
	}
	cleanup()
}

func TestOpen_prodMode(t *testing.T) {
	dir := t.TempDir()
	o := &runtime.Opener{
		ConfigApp: func(devMode bool) *config.App {
			if devMode {
				t.Fatal("expected prod mode")
			}
			return tempApp(dir, false)
		},
	}
	svc, app, cleanup, err := o.Open(false)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	if cleanup == nil || svc == nil || app == nil || app.DevMode {
		t.Fatalf("svc=%v app=%#v cleanup nil=%v", svc, app, cleanup == nil)
	}
	cleanup()
}

func TestOpen_defaultAppBranch(t *testing.T) {
	_, _, _, err := (&runtime.Opener{}).Open(false)
	if err == nil {
		return
	}
	if !strings.Contains(err.Error(), "mkdir data dir") && !strings.Contains(err.Error(), "open store") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpen_defaultStderrOnCloseError(t *testing.T) {
	dir := t.TempDir()
	o := &runtime.Opener{
		ConfigApp: func(bool) *config.App { return tempApp(dir, true) },
		CloseStore: func(*store.Store) error {
			return errors.New("close failed")
		},
	}
	_, _, cleanup, err := o.Open(true)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	cleanup()
}

func TestOpen_mkdirError(t *testing.T) {
	o := &runtime.Opener{
		ConfigApp: func(bool) *config.App { return tempApp(t.TempDir(), true) },
		MkdirAll: func(string, os.FileMode) error {
			return errors.New("mkdir failed")
		},
	}
	_, _, _, err := o.Open(true)
	if err == nil || !strings.Contains(err.Error(), "mkdir data dir") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpen_storeError(t *testing.T) {
	o := &runtime.Opener{
		ConfigApp: func(bool) *config.App { return tempApp(t.TempDir(), true) },
		OpenStore: func(string) (*store.Store, error) {
			return nil, errors.New("store failed")
		},
	}
	_, _, _, err := o.Open(true)
	if err == nil || !strings.Contains(err.Error(), "open store") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpen_manifestError(t *testing.T) {
	o := &runtime.Opener{
		ConfigApp: func(bool) *config.App { return tempApp(t.TempDir(), true) },
		LoadManifest: func(*manifest.Manager) error {
			return errors.New("manifest failed")
		},
	}
	_, _, _, err := o.Open(true)
	if err == nil || !strings.Contains(err.Error(), "load manifest") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpen_cleanupCloseError(t *testing.T) {
	dir := t.TempDir()
	var stderr bytes.Buffer
	o := &runtime.Opener{
		ConfigApp: func(bool) *config.App { return tempApp(dir, true) },
		CloseStore: func(*store.Store) error {
			return errors.New("close failed")
		},
		Stderr: &stderr,
	}
	_, _, cleanup, err := o.Open(true)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	cleanup()
	if !strings.Contains(stderr.String(), "close store: close failed") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestOpenWithOrchestration(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	orch, app, cleanup, err := runtime.OpenWithOrchestration(true)
	if err != nil {
		t.Fatalf("OpenWithOrchestration returned error: %v", err)
	}
	if cleanup == nil {
		t.Fatal("expected non-nil cleanup")
	}
	defer cleanup()
	if orch == nil {
		t.Fatal("expected non-nil orchestration facade")
	}
	if app == nil {
		t.Fatal("expected non-nil app")
	}
	protocols, err := orch.ListProtocolsFromRequest(context.Background(), orchestration.ProtocolListRequest{})
	if err != nil {
		t.Fatalf("list protocols from request: %v", err)
	}
	if len(protocols.Names) == 0 {
		t.Fatal("expected orchestration facade to expose registered protocols")
	}
	bootStatus, err := orch.GetBootstrapStatusFromRequest(context.Background(), orchestration.BootstrapStatusRequest{})
	if err != nil {
		t.Fatalf("bootstrap status from request: %v", err)
	}
	if bootStatus.Bootstrapped {
		t.Fatal("expected fresh dev runtime to be not bootstrapped")
	}
}

func TestOpenWithOrchestration_openError(t *testing.T) {
	o := &runtime.Opener{
		ConfigApp: func(bool) *config.App { return tempApp(t.TempDir(), true) },
		MkdirAll: func(string, os.FileMode) error {
			return errors.New("mkdir failed")
		},
	}
	orch, app, cleanup, err := o.OpenWithOrchestration(true)
	if err == nil {
		t.Fatal("expected error")
	}
	if orch != nil || app != nil || cleanup != nil {
		t.Fatalf("got orch nil=%v app=%v cleanup nil=%v", orch == nil, app, cleanup == nil)
	}
}
