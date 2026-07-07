package cmd_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

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

func TestSystemSSHPortJSON(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir:      dir,
		DBPath:       filepath.Join(dir, "state.db"),
		ConfigPath:   filepath.Join(dir, "sing-box.json"),
		ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode:      true,
		ServerHost:   "example.com",
	}
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
	man.SetSSHPort(2222)
	if err := man.Save(); err != nil {
		t.Fatal(err)
	}
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	devFlag := true
	root := cmd.NewRootCommand(orchestration.New(svc), app, &devFlag, cmd.Options{DevMode: true})
	out := runJSONCommand(t, root, context.Background(), "system", "ssh", "port", "--json")
	var result struct {
		SSHPort int `json:"ssh_port"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if result.SSHPort != 2222 {
		t.Fatalf("unexpected ssh_port: %#v out=%q", result, out)
	}
}

func TestSystemSSHPortText(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir:      dir,
		DBPath:       filepath.Join(dir, "state.db"),
		ConfigPath:   filepath.Join(dir, "sing-box.json"),
		ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode:      true,
		ServerHost:   "example.com",
	}
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
	man.SetSSHPort(3333)
	if err := man.Save(); err != nil {
		t.Fatal(err)
	}
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	devFlag := true
	root := cmd.NewRootCommand(orchestration.New(svc), app, &devFlag, cmd.Options{DevMode: true})
	out, err := runCommand(t, root, context.Background(), "system", "ssh", "port")
	if err != nil {
		t.Fatal(err)
	}
	if out != "3333\n" {
		t.Fatalf("unexpected port text: %q", out)
	}
}

func TestSystemSSHPortSetDevModeError(t *testing.T) {
	root, ctx := newTestRoot(t)
	runJSONCommand(t, root, ctx, "--dev", "--json", "bootstrap", "--yes")
	_, err := runCommand(t, root, ctx, "--dev", "--json", "system", "ssh", "port", "set", "2222")
	if err == nil {
		t.Fatal("expected ssh port set to fail in dev mode")
	}
	if !strings.Contains(err.Error(), "production mode") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSystemSSHPortSetInvalid(t *testing.T) {
	root, ctx := newTestRoot(t)
	_, err := runCommand(t, root, ctx, "--dev", "system", "ssh", "port", "set", "not-a-port")
	if err == nil {
		t.Fatal("expected invalid port error")
	}
}
