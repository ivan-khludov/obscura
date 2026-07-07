package config_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/ivan-khludov/obscura/internal/config"
	"github.com/ivan-khludov/obscura/internal/domain"
)

func TestDefaultApp(t *testing.T) {
	app := config.DefaultApp()
	if app.DataDir != domain.DefaultDataDir {
		t.Fatalf("DataDir = %q, want %q", app.DataDir, domain.DefaultDataDir)
	}
	if app.DBPath != domain.DefaultDBPath {
		t.Fatalf("DBPath = %q, want %q", app.DBPath, domain.DefaultDBPath)
	}
	if app.ConfigPath != domain.DefaultSingBoxConfigPath {
		t.Fatalf("ConfigPath = %q, want %q", app.ConfigPath, domain.DefaultSingBoxConfigPath)
	}
	if app.ManifestPath != domain.DefaultManifestPath {
		t.Fatalf("ManifestPath = %q, want %q", app.ManifestPath, domain.DefaultManifestPath)
	}
	if app.DevMode {
		t.Fatal("expected DevMode false")
	}
	if app.ServerHost == "" {
		t.Fatal("expected non-empty ServerHost")
	}
}

func TestDevApp(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	app := config.DevApp()
	base := filepath.Join(home, ".obscura")
	if app.DataDir != base {
		t.Fatalf("DataDir = %q, want %q", app.DataDir, base)
	}
	if app.DBPath != filepath.Join(base, "state.db") {
		t.Fatalf("DBPath = %q", app.DBPath)
	}
	if app.ConfigPath != filepath.Join(base, "sing-box.json") {
		t.Fatalf("ConfigPath = %q", app.ConfigPath)
	}
	if app.ManifestPath != filepath.Join(base, "manifest.json") {
		t.Fatalf("ManifestPath = %q", app.ManifestPath)
	}
	if !app.DevMode {
		t.Fatal("expected DevMode true")
	}
	if app.ServerHost != "127.0.0.1" {
		t.Fatalf("ServerHost = %q, want 127.0.0.1", app.ServerHost)
	}
}

func TestServerHostFrom_hostnameError(t *testing.T) {
	if got := config.ServerHostFrom("", errors.New("hostname failed")); got != "127.0.0.1" {
		t.Fatalf("ServerHostFrom = %q, want 127.0.0.1", got)
	}
}

func TestServerHostFrom_emptyHostname(t *testing.T) {
	if got := config.ServerHostFrom("", nil); got != "127.0.0.1" {
		t.Fatalf("ServerHostFrom = %q, want 127.0.0.1", got)
	}
}

func TestServerHostFrom_success(t *testing.T) {
	if got := config.ServerHostFrom("my-server", nil); got != "my-server" {
		t.Fatalf("ServerHostFrom = %q, want my-server", got)
	}
}
