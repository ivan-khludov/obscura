package cmd_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/ivan-khludov/obscura/internal/cmd"
	"github.com/ivan-khludov/obscura/internal/config"
	"github.com/ivan-khludov/obscura/internal/firewall"
	"github.com/ivan-khludov/obscura/internal/manifest"
	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/runtime"
	"github.com/ivan-khludov/obscura/internal/service"
	"github.com/ivan-khludov/obscura/internal/singboxcheck"
	"github.com/ivan-khludov/obscura/internal/store"
	"github.com/ivan-khludov/obscura/internal/systemd"
)

func newTestApp(t *testing.T) *config.App {
	t.Helper()
	dir := t.TempDir()
	return &config.App{
		DataDir:      dir,
		DBPath:       filepath.Join(dir, "state.db"),
		ConfigPath:   filepath.Join(dir, "sing-box.json"),
		ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode:      true,
		ServerHost:   "example.com",
	}
}

func newRootFromApp(t *testing.T, app *config.App, devMode *bool, opts cmd.Options) *cobra.Command {
	t.Helper()
	st, err := store.Open(app.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	return cmd.NewRootCommand(orchestration.New(svc), app, devMode, opts)
}

func TestNewRootCommandJSONPreset(t *testing.T) {
	app := newTestApp(t)
	jsonPreset := true
	root := newRootFromApp(t, app, nil, cmd.Options{JSON: &jsonPreset})
	out := runJSONCommand(t, root, context.Background(), "version")
	if !strings.Contains(out, "version") {
		t.Fatalf("expected json version output, got %q", out)
	}
}

func TestNewRootCommandDevModeNil(t *testing.T) {
	app := newTestApp(t)
	root := newRootFromApp(t, app, nil, cmd.Options{})
	if root.PersistentFlags().Lookup("dev") != nil {
		t.Fatal("expected no --dev flag when devMode is nil")
	}
	out, err := runCommand(t, root, context.Background(), "version")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) == "" {
		t.Fatal("expected version output")
	}
}

func TestRootHelp(t *testing.T) {
	root, ctx := newTestRoot(t)
	out, err := runCommand(t, root, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Terminal manager for sing-box VPN servers") {
		t.Fatalf("expected root help text, got %q", out)
	}
}
