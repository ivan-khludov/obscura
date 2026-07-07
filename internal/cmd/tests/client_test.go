package cmd_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/ivan-khludov/obscura/internal/cmd"
	"github.com/ivan-khludov/obscura/internal/config"
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/firewall"
	"github.com/ivan-khludov/obscura/internal/manifest"
	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/runtime"
	"github.com/ivan-khludov/obscura/internal/service"
	"github.com/ivan-khludov/obscura/internal/singboxcheck"
	"github.com/ivan-khludov/obscura/internal/store"
	"github.com/ivan-khludov/obscura/internal/systemd"
)

func setupClientRoot(t *testing.T) (*cobra.Command, context.Context) {
	t.Helper()
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
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	ctx := context.Background()
	_, err = svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: true,
		InitialClientName: "phone",
		Listen:            domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080},
	})
	if err != nil {
		t.Fatal(err)
	}
	devFlag := true
	root := cmd.NewRootCommand(orchestration.New(svc), app, &devFlag, cmd.Options{DevMode: true})
	return root, ctx
}

func newTestRootFromApp(t *testing.T, app *config.App, svc *service.Service) (*cobra.Command, context.Context) {
	t.Helper()
	devFlag := true
	root := cmd.NewRootCommand(orchestration.New(svc), app, &devFlag, cmd.Options{DevMode: true})
	return root, context.Background()
}

func setupClientEnv(t *testing.T) (*config.App, *service.Service, context.Context) {
	t.Helper()
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
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	ctx := context.Background()
	_, err = svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: true,
		InitialClientName: "keep",
		Listen:            domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = svc.AddClient(ctx, service.AddClientInput{VPNName: "main", Name: "phone"}, false)
	if err != nil {
		t.Fatal(err)
	}
	return app, svc, ctx
}

func TestClientShowURI(t *testing.T) {
	root, ctx := setupClientRoot(t)
	out, err := runCommand(t, root, ctx, "client", "show", "--vpn", "main", "--name", "phone")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) < 7 || out[:7] != "socks5:" {
		t.Fatalf("unexpected output: %q", out)
	}
}

func TestClientEditJSON(t *testing.T) {
	root, ctx := newTestRoot(t)
	runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "create", "--name", "main", "--port", "1080", "--client-name", "phone")
	out := runJSONCommand(t, root, ctx, "--dev", "--json", "client", "edit", "--vpn", "main", "--name", "phone", "--new-name", "laptop")
	var client map[string]any
	if err := json.Unmarshal([]byte(out), &client); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if client["Name"] != "laptop" {
		t.Fatalf("unexpected client: %#v", client)
	}
}

func TestClientAddJSON(t *testing.T) {
	root, ctx := newTestRoot(t)
	runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "create", "--name", "main", "--port", "1080", "--client-name", "phone")
	out := runJSONCommand(t, root, ctx, "--dev", "--json", "client", "add", "--vpn", "main", "--name", "tablet", "--no-apply")
	var result struct {
		Client map[string]any `json:"client"`
		URI    string         `json:"uri"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if result.Client["Name"] != "tablet" || !strings.HasPrefix(result.URI, "socks5://") {
		t.Fatalf("unexpected add result: %#v uri=%q", result.Client, result.URI)
	}
}

func TestClientAddQR(t *testing.T) {
	root, ctx := newTestRoot(t)
	runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "create", "--name", "main", "--port", "1080", "--client-name", "phone")
	out, err := runCommand(t, root, ctx, "--dev", "client", "add", "--vpn", "main", "--name", "tablet", "--qr", "--no-apply")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "socks5://") {
		t.Fatalf("expected uri in output: %q", out)
	}
}

func TestClientList(t *testing.T) {
	root, ctx := setupClientRoot(t)
	out := runJSONCommand(t, root, ctx, "--dev", "--json", "client", "list", "--vpn", "main")
	var items []map[string]any
	if err := json.Unmarshal([]byte(out), &items); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if len(items) != 1 || items[0]["Name"] != "phone" {
		t.Fatalf("unexpected list: %#v", items)
	}
}

func TestClientRemove(t *testing.T) {
	root, ctx := newTestRoot(t)
	runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "create", "--name", "main", "--port", "1080", "--client-name", "keep")
	runJSONCommand(t, root, ctx, "--dev", "--json", "client", "add", "--vpn", "main", "--name", "remove-me", "--no-apply")
	root.SetArgs([]string{"--dev", "client", "remove", "--vpn", "main", "--name", "remove-me"})
	if err := root.ExecuteContext(ctx); err != nil {
		t.Fatal(err)
	}
	out := runJSONCommand(t, root, ctx, "--dev", "--json", "client", "list", "--vpn", "main")
	var items []map[string]any
	if err := json.Unmarshal([]byte(out), &items); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if len(items) != 1 || items[0]["Name"] != "keep" {
		t.Fatalf("expected keep client only, got %#v", items)
	}
}

func TestClientRotatePasswordText(t *testing.T) {
	root, ctx := setupClientRoot(t)
	out, err := runCommand(t, root, ctx, "client", "rotate-password", "--vpn", "main", "--name", "phone")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.TrimSpace(out), "socks5://") {
		t.Fatalf("unexpected output: %q", out)
	}
}

func TestClientRotatePasswordQR(t *testing.T) {
	root, ctx := setupClientRoot(t)
	out, err := runCommand(t, root, ctx, "client", "rotate-password", "--vpn", "main", "--name", "phone", "--qr")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "socks5://") {
		t.Fatalf("expected uri in output: %q", out)
	}
}

func TestClientRotatePasswordJSON(t *testing.T) {
	root, ctx := setupClientRoot(t)
	out := runJSONCommand(t, root, ctx, "--dev", "--json", "client", "rotate-password", "--vpn", "main", "--name", "phone")
	var result struct {
		Password string `json:"password"`
		URI      string `json:"uri"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if result.Password == "" || !strings.HasPrefix(result.URI, "socks5://") {
		t.Fatalf("unexpected rotate result: %#v", result)
	}
}

func TestClientEditUsernamePasswordDisabled(t *testing.T) {
	root, ctx := newTestRoot(t)
	runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "create", "--name", "main", "--port", "1080", "--client-name", "keep")
	runJSONCommand(t, root, ctx, "--dev", "--json", "client", "add", "--vpn", "main", "--name", "phone", "--no-apply")
	out := runJSONCommand(t, root, ctx, "--dev", "--json", "client", "edit",
		"--vpn", "main", "--name", "phone",
		"--username", "user1", "--password", "secret", "--disabled", "--apply=false")
	var client map[string]any
	if err := json.Unmarshal([]byte(out), &client); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if client["Username"] != "user1" || client["Enabled"] != false {
		t.Fatalf("unexpected client after edit: %#v", client)
	}
}

func TestClientEditEnabled(t *testing.T) {
	app, svc, ctx := setupClientEnv(t)
	disableRoot, _ := newTestRootFromApp(t, app, svc)
	runJSONCommand(t, disableRoot, ctx, "--dev", "--json", "client", "edit",
		"--vpn", "main", "--name", "phone", "--disabled", "--apply=false")
	enableRoot, _ := newTestRootFromApp(t, app, svc)
	out := runJSONCommand(t, enableRoot, ctx, "--dev", "--json", "client", "edit",
		"--vpn", "main", "--name", "phone", "--enabled=true", "--apply=false")
	var client map[string]any
	if err := json.Unmarshal([]byte(out), &client); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if client["Enabled"] != true {
		t.Fatalf("expected enabled client, got %#v", client)
	}
}
