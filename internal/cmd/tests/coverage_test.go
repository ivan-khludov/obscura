package cmd_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/ivan-khludov/obscura/internal/apply"
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

func newTestRootWithSystemd(t *testing.T, mgr apply.ServiceManager) (*cobra.Command, context.Context, *config.App) {
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
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, mgr)
	devFlag := true
	root := cmd.NewRootCommand(orchestration.New(svc), app, &devFlag, cmd.Options{DevMode: true})
	return root, context.Background(), app
}

func newProdTestRoot(t *testing.T) (*cobra.Command, context.Context) {
	t.Helper()
	dir := t.TempDir()
	app := &config.App{
		DataDir:      dir,
		DBPath:       filepath.Join(dir, "state.db"),
		ConfigPath:   filepath.Join(dir, "sing-box.json"),
		ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode:      false,
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
	devFlag := false
	root := cmd.NewRootCommand(orchestration.New(svc), app, &devFlag, cmd.Options{DevMode: false})
	return root, context.Background()
}

func TestBootstrapConfirmStdinY(t *testing.T) {
	root, ctx := newTestRoot(t)
	out, err := runCommandWithStdin(t, root, ctx, "y\n", "--dev", "--json", "bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "bootstrapped") {
		t.Fatalf("expected bootstrap success, got %q", out)
	}
}

func TestVPNCreateDuplicateError(t *testing.T) {
	root, ctx := newTestRoot(t)
	runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "create", "--name", "main", "--port", "1080", "--client-name", "phone")
	_, err := runCommand(t, root, ctx, "--dev", "--json", "vpn", "create", "--name", "main", "--port", "1081", "--client-name", "other")
	if err == nil {
		t.Fatal("expected duplicate vpn create error")
	}
}

func TestVPNEditNotFound(t *testing.T) {
	root, ctx := newTestRoot(t)
	_, err := runCommand(t, root, ctx, "--dev", "--json", "vpn", "edit", "missing", "--port", "1080")
	if err == nil {
		t.Fatal("expected vpn edit not found error")
	}
}

func TestVPNShowNotFound(t *testing.T) {
	root, ctx := newTestRoot(t)
	_, err := runCommand(t, root, ctx, "--dev", "--json", "vpn", "show", "missing")
	if err == nil {
		t.Fatal("expected vpn show not found error")
	}
}

func TestVPNEditClientHost(t *testing.T) {
	root, ctx := newTestRoot(t)
	runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "create", "--name", "main", "--port", "1080", "--client-name", "phone")
	out := runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "edit", "main", "--client-host", "vpn.example.com", "--apply=false")
	if !strings.Contains(out, "vpn.example.com") {
		t.Fatalf("expected client host in output, got %q", out)
	}
}

func TestClientAddInvalidVPN(t *testing.T) {
	root, ctx := newTestRoot(t)
	_, err := runCommand(t, root, ctx, "--dev", "--json", "client", "add", "--vpn", "missing", "--name", "x")
	if err == nil {
		t.Fatal("expected client add error for missing vpn")
	}
}

func TestClientShowInvalid(t *testing.T) {
	root, ctx := newTestRoot(t)
	_, err := runCommand(t, root, ctx, "client", "show", "--vpn", "missing", "--name", "x")
	if err == nil {
		t.Fatal("expected client show error")
	}
}

func TestClientListInvalidVPN(t *testing.T) {
	root, ctx := newTestRoot(t)
	_, err := runCommand(t, root, ctx, "--dev", "--json", "client", "list", "--vpn", "missing")
	if err == nil {
		t.Fatal("expected client list error")
	}
}

func TestClientRotateInvalid(t *testing.T) {
	root, ctx := newTestRoot(t)
	_, err := runCommand(t, root, ctx, "client", "rotate-password", "--vpn", "missing", "--name", "x")
	if err == nil {
		t.Fatal("expected rotate password error")
	}
}

func TestClientEditInvalid(t *testing.T) {
	root, ctx := newTestRoot(t)
	_, err := runCommand(t, root, ctx, "--dev", "--json", "client", "edit", "--vpn", "missing", "--name", "x", "--new-name", "y")
	if err == nil {
		t.Fatal("expected client edit error")
	}
}

func TestUninstallWithoutFullError(t *testing.T) {
	root, ctx := newTestRoot(t)
	_, err := runCommand(t, root, ctx, "--dev", "uninstall")
	if err == nil {
		t.Fatal("expected uninstall without --full error")
	}
}

func TestNetworkCongestionSetDifferentAlgorithmError(t *testing.T) {
	root, ctx := newTestRoot(t)
	listOut := runJSONCommand(t, root, ctx, "--dev", "--json", "network", "congestion", "list")
	var list struct {
		Current   string   `json:"current"`
		Available []string `json:"available"`
	}
	if err := json.Unmarshal([]byte(listOut), &list); err != nil {
		t.Fatal(err)
	}
	var other string
	for _, alg := range list.Available {
		if alg != list.Current {
			other = alg
			break
		}
	}
	if other == "" {
		t.Skip("no alternate congestion algorithm available")
	}
	_, err := runCommand(t, root, ctx, "--dev", "--json", "network", "congestion", "set", other)
	if err == nil {
		t.Fatal("expected congestion set error in dev mode")
	}
}

func TestBackupCreateReadonlyDirError(t *testing.T) {
	root, ctx, app := newTestRootWithSystemd(t, systemd.NopManager{})
	runJSONCommand(t, root, ctx, "--dev", "--json", "bootstrap", "--yes")
	backupDir := filepath.Join(app.DataDir, "backups")
	if err := os.Chmod(backupDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(backupDir, 0o755) })
	_, err := runCommand(t, root, ctx, "--dev", "--json", "backup", "create")
	if err == nil {
		t.Fatal("expected backup create error with read-only backup dir")
	}
}

func TestApplyCheckerError(t *testing.T) {
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
	t.Cleanup(func() { _ = st.Close() })
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	checker := failChecker{}
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, checker, systemd.NopManager{})
	ctx := context.Background()
	_, err = svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: false,
		InitialClientName: "phone",
		Listen:            domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080},
	})
	if err != nil {
		t.Fatal(err)
	}
	devFlag := true
	root := cmd.NewRootCommand(orchestration.New(svc), app, &devFlag, cmd.Options{DevMode: true})
	_, err = runCommand(t, root, ctx, "--dev", "--json", "apply")
	if err == nil {
		t.Fatal("expected apply error from failing checker")
	}
}

type failChecker struct{ singboxcheck.NopChecker }

func (failChecker) Check(_ context.Context, _ string) error {
	return errors.New("checker failed")
}

func TestSystemSSHPortSetProductionNoOp(t *testing.T) {
	root, ctx := newProdTestRoot(t)
	out, err := runCommand(t, root, ctx, "system", "ssh", "port")
	if err != nil {
		t.Skipf("cannot read ssh port in this environment: %v", err)
	}
	port := strings.TrimSpace(out)
	setRoot, setCtx := newProdTestRoot(t)
	out, err = runCommand(t, setRoot, setCtx, "system", "ssh", "port", "set", port)
	if err != nil {
		t.Skipf("ssh port set unavailable in this environment: %v", err)
	}
	if !strings.Contains(out, "ssh_port") {
		t.Fatalf("unexpected set output: %q", out)
	}
}

func TestPrintQRForTestError(t *testing.T) {
	err := cmd.PrintQRForTest(strings.Repeat("x", 4000))
	if err == nil {
		t.Fatal("expected qr render error for oversized content")
	}
}

func TestBootstrapErrorReadonlyManifest(t *testing.T) {
	root, ctx, app := newTestRootWithSystemd(t, systemd.NopManager{})
	runJSONCommand(t, root, ctx, "--dev", "--json", "bootstrap", "--yes")
	if err := os.Chmod(app.ManifestPath, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(app.ManifestPath, 0o644) })
	_, err := runCommand(t, root, ctx, "--dev", "--json", "bootstrap", "--yes")
	if err == nil {
		t.Fatal("expected bootstrap error with read-only manifest")
	}
}

func TestClientShowWithQR(t *testing.T) {
	root, ctx := setupClientRoot(t)
	out, err := runCommand(t, root, ctx, "client", "show", "--vpn", "main", "--name", "phone", "--qr")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "socks5://") {
		t.Fatalf("expected uri with qr output, got %q", out)
	}
}

func TestClientAddWithQRErrorPath(t *testing.T) {
	root, ctx := newTestRoot(t)
	runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "create", "--name", "main", "--port", "1080", "--client-name", "phone")
	_, err := runCommand(t, root, ctx, "--dev", "client", "add", "--vpn", "main", "--name", "phone", "--qr")
	if err == nil {
		t.Fatal("expected client add duplicate error")
	}
}

func TestBackupRestoreInvalidPath(t *testing.T) {
	root, ctx := newTestRoot(t)
	runJSONCommand(t, root, ctx, "--dev", "--json", "bootstrap", "--yes")
	_, err := runCommand(t, root, ctx, "--dev", "backup", "restore", "/nonexistent/archive.tar.gz")
	if err == nil {
		t.Fatal("expected backup restore error")
	}
}

func TestVPNEditDuplicateNameError(t *testing.T) {
	root, ctx := newTestRoot(t)
	runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "create", "--name", "main", "--port", "1080", "--client-name", "phone")
	runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "create", "--name", "other", "--port", "1081", "--client-name", "phone")
	_, err := runCommand(t, root, ctx, "--dev", "--json", "vpn", "edit", "main", "--new-name", "other", "--apply=false")
	if err == nil {
		t.Fatal("expected vpn edit duplicate name error")
	}
}

func TestVPNListClosedStoreError(t *testing.T) {
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
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	devFlag := true
	root := cmd.NewRootCommand(orchestration.New(svc), app, &devFlag, cmd.Options{DevMode: true})
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = runCommand(t, root, context.Background(), "--dev", "--json", "vpn", "list")
	if err == nil {
		t.Fatal("expected vpn list error after store closed")
	}
}

func TestFetchClientQRForAddError(t *testing.T) {
	_, ctx := newTestRoot(t)
	app, svc, _ := setupClientEnv(t)
	orch := orchestration.New(svc)
	_, err := cmd.FetchClientQRForAddForTest(ctx, orch, "missing", "client")
	if err == nil {
		t.Fatal("expected fetch client qr error")
	}
	err = cmd.ClientAddAfterCreateForTest(ctx, orch, false, "missing", "client", true, map[string]string{"Name": "client"}, "socks5://x")
	if err == nil {
		t.Fatal("expected client add after create qr error")
	}
	root, _ := newTestRootFromApp(t, app, svc)
	_, err = runCommand(t, root, ctx, "--dev", "client", "add", "--vpn", "missing", "--name", "x", "--qr")
	if err == nil {
		t.Fatal("expected client add error before qr fetch")
	}
}
func TestStatusAfterClose(t *testing.T) {
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
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	devFlag := true
	root := cmd.NewRootCommand(orchestration.New(svc), app, &devFlag, cmd.Options{DevMode: true})
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = runCommand(t, root, context.Background(), "--dev", "--json", "status")
	if err == nil {
		t.Fatal("expected status error after store closed")
	}
}
