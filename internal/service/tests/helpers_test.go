package service_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/apply"
	"github.com/ivan-khludov/obscura/internal/config"
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/firewall"
	"github.com/ivan-khludov/obscura/internal/manifest"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/runtime"
	"github.com/ivan-khludov/obscura/internal/service"
	"github.com/ivan-khludov/obscura/internal/singboxcheck"
	"github.com/ivan-khludov/obscura/internal/sshd"
	"github.com/ivan-khludov/obscura/internal/store"
	"github.com/ivan-khludov/obscura/internal/systemd"
)

type trackingFirewall struct {
	deleted    []string
	allowed    []string
	enablePort int
	enabled    bool
}

func (f *trackingFirewall) AllowPort(_ context.Context, port int, proto string) (string, error) {
	rule := fmt.Sprintf("%d/%s", port, proto)
	f.allowed = append(f.allowed, rule)
	return rule, nil
}

func (f *trackingFirewall) DeleteRule(_ context.Context, spec string) error {
	f.deleted = append(f.deleted, spec)
	return nil
}

func (f *trackingFirewall) Enable(_ context.Context, sshPort int) error {
	f.enabled = true
	f.enablePort = sshPort
	return nil
}

func (f *trackingFirewall) IsAvailable() bool { return true }

type errorFirewall struct{}

func (errorFirewall) AllowPort(_ context.Context, _ int, _ string) (string, error) {
	return "", fmt.Errorf("firewall denied")
}
func (errorFirewall) DeleteRule(_ context.Context, _ string) error { return nil }
func (errorFirewall) Enable(_ context.Context, _ int) error        { return nil }
func (errorFirewall) IsAvailable() bool                            { return true }

type checkRecorder struct {
	called bool
}

func (c *checkRecorder) Check(_ context.Context, _ string) error {
	c.called = true
	return nil
}

type reloadRecorder struct {
	called bool
}

func (r *reloadRecorder) Reload(_ context.Context) error {
	r.called = true
	return nil
}

func (r *reloadRecorder) IsActive(_ context.Context) (bool, error) { return false, nil }

var _ apply.ServiceManager = (*reloadRecorder)(nil)

func stubSSHKeepalive(t *testing.T, dir string) *sshd.Keepalive {
	t.Helper()
	confPath := filepath.Join(dir, "sshd_config.d", "99-obscura.conf")
	return &sshd.Keepalive{
		ConfPath: confPath,
		Config:   &sshd.Config{ReadFile: os.ReadFile, WriteFile: os.WriteFile},
		Runner: &sshd.Runner{
			RunCommand: func(context.Context, string, ...string) ([]byte, error) {
				return nil, nil
			},
		},
	}
}

func wireStubSSHKeepalive(t *testing.T, svc *service.Service, dir string) {
	t.Helper()
	svc.SetSSHKeepaliveForTest(stubSSHKeepalive(t, dir))
}

func newTestService(t *testing.T) (*service.Service, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	app := &config.App{
		DataDir:      dir,
		DBPath:       filepath.Join(dir, "state.db"),
		ConfigPath:   filepath.Join(dir, "sing-box.json"),
		ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode:      true,
		ServerHost:   "127.0.0.1",
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	wireStubSSHKeepalive(t, svc, dir)
	return svc, st
}

func mustOpenStore(t *testing.T, dbPath string) *store.Store {
	t.Helper()
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	return st
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestSanitizeNameForTest(t *testing.T) {
	if got := service.SanitizeNameForTest(" My VPN "); got != "my-vpn" {
		t.Fatalf("got %q", got)
	}
}

func TestNeedsInitialClientForTest(t *testing.T) {
	reg := runtime.NewProtocolRegistry()
	adapter, _ := reg.Get("socks5")
	if !service.NeedsInitialClientForTest(adapter, service.ToVPNConfigForTest(&domain.VPN{Protocol: "socks5"})) {
		t.Fatal("socks5 needs initial client")
	}
}

func TestRandomPasswordForTest(t *testing.T) {
	pw, err := service.RandomPasswordForTest(nil, 16)
	if err != nil || len(pw) != 16 {
		t.Fatalf("password: %q err=%v", pw, err)
	}
}

func TestRandomPasswordForTestReadError(t *testing.T) {
	_, err := service.RandomPasswordForTest(&service.PasswordGen{RandRead: errReader{}}, 16)
	if err == nil {
		t.Fatal("expected read error")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, fmt.Errorf("read failed") }

type failChecker struct{}

func (failChecker) Check(_ context.Context, _ string) error {
	return fmt.Errorf("check failed")
}

type clientRequiredProtocol struct{}

func (clientRequiredProtocol) Type() string { return "stub" }
func (clientRequiredProtocol) ValidateVPN(domain.VPNConfig, []domain.ClientConfig) error {
	return fmt.Errorf("at least one enabled client required")
}
func (clientRequiredProtocol) ValidateClient(domain.ClientConfig) error { return nil }
func (clientRequiredProtocol) RenderInbound(domain.VPNConfig, []domain.ClientConfig) (map[string]any, error) {
	return nil, nil
}
func (clientRequiredProtocol) RenderEndpoints(domain.VPNConfig, []domain.ClientConfig) ([]map[string]any, error) {
	return nil, nil
}
func (clientRequiredProtocol) AdditionalInbounds(domain.VPNConfig, []domain.ClientConfig) ([]map[string]any, error) {
	return nil, nil
}
func (clientRequiredProtocol) ClientURI(domain.VPNConfig, []domain.ClientConfig, domain.ClientConfig, string) (string, error) {
	return "", nil
}
func (clientRequiredProtocol) ClientQRContent(domain.VPNConfig, []domain.ClientConfig, domain.ClientConfig, string) (string, error) {
	return "", nil
}
func (clientRequiredProtocol) DefaultListen() domain.ListenOptions {
	return domain.DefaultListenOptions()
}
func (clientRequiredProtocol) SupportedListenFields() []string { return nil }
func (clientRequiredProtocol) RouteExtensions(domain.VPNConfig) ([]map[string]any, error) {
	return nil, nil
}
func (clientRequiredProtocol) UsesInbound() bool        { return true }
func (clientRequiredProtocol) FirewallProtos() []string { return []string{"tcp"} }
func (clientRequiredProtocol) BuildProtocolData(protocol.BuildContext, domain.CreateVPNSpec, string, protocol.BuildMode) ([]byte, error) {
	return []byte("{}"), nil
}
func (clientRequiredProtocol) NeedsInitialClient(domain.VPNConfig) bool { return true }

type clientValidateOnlyProtocol struct{}

func (clientValidateOnlyProtocol) Type() string { return "clientonly" }
func (clientValidateOnlyProtocol) ValidateVPN(domain.VPNConfig, []domain.ClientConfig) error {
	return fmt.Errorf("at least one enabled client required")
}
func (clientValidateOnlyProtocol) ValidateClient(domain.ClientConfig) error { return nil }
func (clientValidateOnlyProtocol) RenderInbound(domain.VPNConfig, []domain.ClientConfig) (map[string]any, error) {
	return nil, nil
}
func (clientValidateOnlyProtocol) RenderEndpoints(domain.VPNConfig, []domain.ClientConfig) ([]map[string]any, error) {
	return nil, nil
}
func (clientValidateOnlyProtocol) AdditionalInbounds(domain.VPNConfig, []domain.ClientConfig) ([]map[string]any, error) {
	return nil, nil
}
func (clientValidateOnlyProtocol) ClientURI(domain.VPNConfig, []domain.ClientConfig, domain.ClientConfig, string) (string, error) {
	return "", nil
}
func (clientValidateOnlyProtocol) ClientQRContent(domain.VPNConfig, []domain.ClientConfig, domain.ClientConfig, string) (string, error) {
	return "", nil
}
func (clientValidateOnlyProtocol) DefaultListen() domain.ListenOptions {
	return domain.DefaultListenOptions()
}
func (clientValidateOnlyProtocol) SupportedListenFields() []string { return nil }
func (clientValidateOnlyProtocol) RouteExtensions(domain.VPNConfig) ([]map[string]any, error) {
	return nil, nil
}
func (clientValidateOnlyProtocol) UsesInbound() bool        { return true }
func (clientValidateOnlyProtocol) FirewallProtos() []string { return []string{"tcp"} }

type draftValidateFailProtocol struct{ okProtocol }

func (draftValidateFailProtocol) Type() string { return "draftfail" }
func (draftValidateFailProtocol) ValidateVPN(domain.VPNConfig, []domain.ClientConfig) error {
	return fmt.Errorf("invalid vpn config")
}

type previewValidateFailProtocol struct{ okProtocol }

func (previewValidateFailProtocol) Type() string { return "prevfail" }
func (previewValidateFailProtocol) ValidateVPN(domain.VPNConfig, []domain.ClientConfig) error {
	return fmt.Errorf("invalid vpn config")
}

type okProtocol struct{ clientRequiredProtocol }

func (okProtocol) ValidateVPN(domain.VPNConfig, []domain.ClientConfig) error { return nil }
func (okProtocol) NeedsInitialClient(domain.VPNConfig) bool                  { return false }

func TestNeedsInitialClientValidateFallback(t *testing.T) {
	if !service.NeedsInitialClientForTest(clientRequiredProtocol{}, domain.VPNConfig{}) {
		t.Fatal("expected client required via validate error")
	}
	if service.NeedsInitialClientForTest(okProtocol{}, domain.VPNConfig{}) {
		t.Fatal("expected false when validate ok")
	}
	if !service.NeedsInitialClientForTest(clientValidateOnlyProtocol{}, domain.VPNConfig{}) {
		t.Fatal("expected client required via validate-only adapter")
	}
	if service.NeedsInitialClientForTest(bareProtocol{}, domain.VPNConfig{}) {
		t.Fatal("expected false for validate-only adapter with nil error")
	}
}

func TestSetPasswordGenForTest(t *testing.T) {
	svc, _ := newTestService(t)
	svc.SetPasswordGenForTest(service.PasswordGen{RandRead: strings.NewReader("abcdefghijklmnop")})
	pw, err := svc.GeneratePassword(8)
	if err != nil || pw == "" {
		t.Fatalf("password=%q err=%v", pw, err)
	}
}

func closedStoreService(t *testing.T) *service.Service {
	t.Helper()
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: true, ServerHost: "127.0.0.1",
	}
	st, err := store.Open(app.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	return svc
}

func customRegistry(t *testing.T, extra ...protocol.Protocol) *protocol.Registry {
	t.Helper()
	reg := protocol.NewRegistry()
	for _, p := range extra {
		reg.Register(p)
	}
	return reg
}

type validateVPNFailProtocol struct{ okProtocol }

func (validateVPNFailProtocol) Type() string                             { return "valfail" }
func (validateVPNFailProtocol) NeedsInitialClient(domain.VPNConfig) bool { return false }
func (validateVPNFailProtocol) ValidateVPN(_ domain.VPNConfig, clientConfigs []domain.ClientConfig) error {
	if len(clientConfigs) > 0 {
		return fmt.Errorf("vpn invalid with clients")
	}
	return nil
}
func (validateVPNFailProtocol) BuildProtocolData(protocol.BuildContext, domain.CreateVPNSpec, string, protocol.BuildMode) ([]byte, error) {
	return []byte("{}"), nil
}

type noInitialClientProtocol struct{ okProtocol }

func (noInitialClientProtocol) Type() string                             { return "noclient" }
func (noInitialClientProtocol) NeedsInitialClient(domain.VPNConfig) bool { return false }
func (noInitialClientProtocol) BuildProtocolData(protocol.BuildContext, domain.CreateVPNSpec, string, protocol.BuildMode) ([]byte, error) {
	return []byte("{}"), nil
}

type bareProtocol struct{}

func (bareProtocol) Type() string                                              { return "bare" }
func (bareProtocol) ValidateVPN(domain.VPNConfig, []domain.ClientConfig) error { return nil }
func (bareProtocol) ValidateClient(domain.ClientConfig) error                  { return nil }
func (bareProtocol) RenderInbound(domain.VPNConfig, []domain.ClientConfig) (map[string]any, error) {
	return map[string]any{"type": "direct"}, nil
}
func (bareProtocol) RenderEndpoints(domain.VPNConfig, []domain.ClientConfig) ([]map[string]any, error) {
	return nil, nil
}
func (bareProtocol) AdditionalInbounds(domain.VPNConfig, []domain.ClientConfig) ([]map[string]any, error) {
	return nil, nil
}
func (bareProtocol) ClientURI(domain.VPNConfig, []domain.ClientConfig, domain.ClientConfig, string) (string, error) {
	return "bare://x", nil
}
func (bareProtocol) ClientQRContent(domain.VPNConfig, []domain.ClientConfig, domain.ClientConfig, string) (string, error) {
	return "bare://x", nil
}
func (bareProtocol) DefaultListen() domain.ListenOptions { return domain.DefaultListenOptions() }
func (bareProtocol) SupportedListenFields() []string     { return nil }
func (bareProtocol) RouteExtensions(domain.VPNConfig) ([]map[string]any, error) {
	return nil, nil
}
func (bareProtocol) UsesInbound() bool        { return true }
func (bareProtocol) FirewallProtos() []string { return []string{"tcp"} }

type invalidClientProtocol struct{ okProtocol }

func (invalidClientProtocol) Type() string { return "badclient" }
func (invalidClientProtocol) ValidateClient(domain.ClientConfig) error {
	return fmt.Errorf("invalid client")
}

type uriFailProtocol struct{ okProtocol }

func (uriFailProtocol) Type() string                             { return "urifail" }
func (uriFailProtocol) NeedsInitialClient(domain.VPNConfig) bool { return true }
func (uriFailProtocol) ClientURI(domain.VPNConfig, []domain.ClientConfig, domain.ClientConfig, string) (string, error) {
	return "", fmt.Errorf("uri failed")
}
func (uriFailProtocol) BuildProtocolData(protocol.BuildContext, domain.CreateVPNSpec, string, protocol.BuildMode) ([]byte, error) {
	return []byte("{}"), nil
}

type enableFirewall struct{ errorFirewall }

func (enableFirewall) Enable(_ context.Context, _ int) error {
	return fmt.Errorf("firewall enable failed")
}

type allowFailFirewall struct{ trackingFirewall }

func (allowFailFirewall) AllowPort(_ context.Context, _ int, _ string) (string, error) {
	return "", fmt.Errorf("allow failed")
}

type qrFailProtocol struct{ okProtocol }

func (qrFailProtocol) Type() string { return "qrfail" }
func (qrFailProtocol) ClientQRContent(domain.VPNConfig, []domain.ClientConfig, domain.ClientConfig, string) (string, error) {
	return "", fmt.Errorf("qr failed")
}
func (qrFailProtocol) BuildProtocolData(protocol.BuildContext, domain.CreateVPNSpec, string, protocol.BuildMode) ([]byte, error) {
	return []byte("{}"), nil
}

type buildFailProtocol struct{ okProtocol }

func (buildFailProtocol) Type() string { return "buildfail" }
func (buildFailProtocol) BuildProtocolData(protocol.BuildContext, domain.CreateVPNSpec, string, protocol.BuildMode) ([]byte, error) {
	return nil, fmt.Errorf("build failed")
}

type applyFailReload struct{}

func (applyFailReload) Reload(_ context.Context) error           { return fmt.Errorf("apply failed") }
func (applyFailReload) IsActive(_ context.Context) (bool, error) { return false, nil }

var _ apply.ServiceManager = (*applyFailReload)(nil)

type faultStore struct {
	inner                 *store.Store
	getVPNByNameErr       error
	listClientsErr        error
	createClientErr       error
	getClientByNameErr    error
	deleteClientErr       error
	listEnabledClientsErr error
	updateClientErr       error
	listVPNsErr           error
	listEnabledVPNsErr    error
	createVPNErr          error
	updateVPNErr          error
	deleteVPNErr          error
}

func (f *faultStore) CreateVPN(ctx context.Context, vpn *domain.VPN) error {
	if f.createVPNErr != nil {
		return f.createVPNErr
	}
	return f.inner.CreateVPN(ctx, vpn)
}

func (f *faultStore) UpdateVPN(ctx context.Context, vpn *domain.VPN) error {
	if f.updateVPNErr != nil {
		return f.updateVPNErr
	}
	return f.inner.UpdateVPN(ctx, vpn)
}

func (f *faultStore) DeleteVPN(ctx context.Context, id int64) error {
	if f.deleteVPNErr != nil {
		return f.deleteVPNErr
	}
	return f.inner.DeleteVPN(ctx, id)
}

func (f *faultStore) GetVPNByName(ctx context.Context, name string) (*domain.VPN, error) {
	if f.getVPNByNameErr != nil {
		return nil, f.getVPNByNameErr
	}
	return f.inner.GetVPNByName(ctx, name)
}

func (f *faultStore) ListVPNs(ctx context.Context) ([]domain.VPN, error) {
	if f.listVPNsErr != nil {
		return nil, f.listVPNsErr
	}
	return f.inner.ListVPNs(ctx)
}

func (f *faultStore) ListEnabledVPNs(ctx context.Context) ([]domain.VPN, error) {
	if f.listEnabledVPNsErr != nil {
		return nil, f.listEnabledVPNsErr
	}
	return f.inner.ListEnabledVPNs(ctx)
}

func (f *faultStore) CreateClient(ctx context.Context, client *domain.Client) error {
	if f.createClientErr != nil {
		return f.createClientErr
	}
	return f.inner.CreateClient(ctx, client)
}

func (f *faultStore) UpdateClient(ctx context.Context, client *domain.Client) error {
	if f.updateClientErr != nil {
		return f.updateClientErr
	}
	return f.inner.UpdateClient(ctx, client)
}

func (f *faultStore) DeleteClient(ctx context.Context, id int64) error {
	if f.deleteClientErr != nil {
		return f.deleteClientErr
	}
	return f.inner.DeleteClient(ctx, id)
}

func (f *faultStore) GetClientByName(ctx context.Context, vpnID int64, name string) (*domain.Client, error) {
	if f.getClientByNameErr != nil {
		return nil, f.getClientByNameErr
	}
	return f.inner.GetClientByName(ctx, vpnID, name)
}

func (f *faultStore) ListClientsByVPN(ctx context.Context, vpnID int64) ([]domain.Client, error) {
	if f.listClientsErr != nil {
		return nil, f.listClientsErr
	}
	return f.inner.ListClientsByVPN(ctx, vpnID)
}

func (f *faultStore) ListEnabledClientsByVPN(ctx context.Context, vpnID int64) ([]domain.Client, error) {
	if f.listEnabledClientsErr != nil {
		return nil, f.listEnabledClientsErr
	}
	return f.inner.ListEnabledClientsByVPN(ctx, vpnID)
}

func wrapFaultStore(st *store.Store) *faultStore {
	return &faultStore{inner: st}
}
