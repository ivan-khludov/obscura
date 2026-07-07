package service_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/config"
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/firewall"
	"github.com/ivan-khludov/obscura/internal/manifest"
	"github.com/ivan-khludov/obscura/internal/protocol/vless"
	"github.com/ivan-khludov/obscura/internal/runtime"
	"github.com/ivan-khludov/obscura/internal/service"
	"github.com/ivan-khludov/obscura/internal/singboxcheck"
	"github.com/ivan-khludov/obscura/internal/systemd"
)

func TestValidateUniquePort(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "first", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1094},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "second", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1094},
	}); err == nil {
		t.Fatal("expected duplicate port error")
	}
}

// TestCreateVPNHTTP verifies HTTP proxy VPN creation stores protocol data and URI.
func TestValidateVPNNameDuplicate(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080},
	}); err != nil {
		t.Fatal(err)
	}
	err := svc.ValidateVPNName(ctx, "main")
	if err == nil {
		t.Fatal("expected duplicate name error")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestValidateVPNListenPortDuplicate verifies duplicate listen port is rejected.
func TestValidateVPNListenPortDuplicate(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080},
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.ValidateVPNListenPort(ctx, 1080); err == nil {
		t.Fatal("expected duplicate port error")
	}
}

// TestValidateCreateVPNDraftSocks5 verifies draft validation for a simple VPN.
func TestValidateCreateVPNDraftSocks5(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if err := svc.ValidateCreateVPNDraft(ctx, service.CreateVPNInput{
		Name: "new", Protocol: "socks5", Enabled: true,
		Listen:            domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1090},
		InitialClientName: "phone",
	}); err != nil {
		t.Fatal(err)
	}
}

// TestCreateVPNOnSSHPort verifies VPN listen port cannot equal SSH port.
func TestValidateCreateVPNDraftPreviewNoCertFiles(t *testing.T) {
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
	ctx := context.Background()
	if err := svc.ValidateCreateVPNDraft(ctx, service.CreateVPNInput{
		Name: "vl", Protocol: "vless", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1443},
		VLESS:  service.VLESSCreateOptions{ServerName: "example.com"},
	}); err != nil {
		t.Fatal(err)
	}
	certsDir := filepath.Join(dir, "certs")
	if entries, err := os.ReadDir(certsDir); err == nil && len(entries) > 0 {
		t.Fatalf("expected no cert files after draft validation, got %d files", len(entries))
	}
}

// TestValidateCreateVPNWizardStepVlessVisionGRPC verifies transport-step validation.
func TestValidateCreateVPNWizardStepVlessVisionGRPC(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	err := svc.ValidateCreateVPNWizardStep(ctx, service.CreateVPNInput{
		Name: "vl", Protocol: "vless", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1443},
		VLESS: service.VLESSCreateOptions{
			DefaultFlow: vless.FlowVision,
			Transport:   "grpc",
			ServerName:  "example.com",
		},
	}, service.WizardAfterTransport)
	if err == nil {
		t.Fatal("expected flow/transport error")
	}
	if !strings.Contains(err.Error(), "direct transport") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestValidateCreateVPNWizardStepHy2BandwidthConflict verifies hysteria2 bandwidth rules at step.
func TestValidateCreateVPNWizardStepHy2BandwidthConflict(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	err := svc.ValidateCreateVPNWizardStep(ctx, service.CreateVPNInput{
		Name: "hy", Protocol: "hysteria2", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1443},
		Hysteria2: service.Hysteria2CreateOptions{
			ServerName:            "example.com",
			UpMbps:                100,
			DownMbps:              100,
			IgnoreClientBandwidth: true,
		},
	}, service.WizardAfterHy2Bandwidth)
	if err == nil {
		t.Fatal("expected bandwidth conflict error")
	}
	if !strings.Contains(err.Error(), "ignore_client_bandwidth") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateCreateVPNWizardSteps(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	base := service.CreateVPNInput{
		Name: "vl", Protocol: "vless", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1443},
		VLESS:  service.VLESSCreateOptions{ServerName: "example.com"},
	}
	steps := []service.WizardValidateStep{
		service.WizardAfterPort,
		service.WizardAfterSNI,
		service.WizardAfterVlessFlow,
		service.WizardAfterTransportDetail,
		service.WizardAfterFallback,
		service.WizardAfterHy2Masquerade,
		service.WizardAfterWireguardSubnet,
		service.WizardAfterWireguardMTU,
		service.WizardComplete,
	}
	for _, step := range steps {
		if err := svc.ValidateCreateVPNWizardStep(ctx, base, step); err != nil {
			t.Fatalf("step %d: %v", step, err)
		}
	}
	if err := svc.ValidateCreateVPNWizardStep(ctx, service.CreateVPNInput{}, service.WizardValidateStep(99)); err != nil {
		t.Fatal(err)
	}
}

func TestValidateVPNNameEmpty(t *testing.T) {
	svc, _ := newTestService(t)
	if err := svc.ValidateVPNName(context.Background(), "  "); err == nil {
		t.Fatal("expected empty name error")
	}
}

func TestPreviewNameWithValue(t *testing.T) {
	if got := service.PreviewNameForTest("myvpn"); got != "myvpn" {
		t.Fatalf("got %q", got)
	}
}

func TestValidateCreateVPNInputFieldsAll(t *testing.T) {
	cases := []service.CreateVPNInput{
		{Protocol: "socks5", SSMethod: "x"},
		{Protocol: "socks5", SSMultiplex: true},
		{Protocol: "socks5", HTTP: service.HTTPCreateOptions{TLS: true}},
		{Protocol: "socks5", Wireguard: service.WireguardCreateOptions{Address: []string{"10.0.0.1/24"}}},
	}
	for i, in := range cases {
		if err := service.ValidateCreateVPNInputFieldsForTest(in); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
}

func TestValidateCreateVPNDraftErrors(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if err := svc.ValidateCreateVPNDraft(ctx, service.CreateVPNInput{
		Name: "x", Protocol: "unknown", Listen: domain.ListenOptions{ListenPort: 15001},
	}); err == nil {
		t.Fatal("expected unknown protocol")
	}
	if err := svc.ValidateCreateVPNDraft(ctx, service.CreateVPNInput{
		Name: "bad name!!!", Protocol: "vless", Listen: domain.ListenOptions{ListenPort: 15002},
		VLESS: service.VLESSCreateOptions{DefaultFlow: "vision", Transport: "grpc", ServerName: "example.com"},
	}); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateVPNNameClosedStore(t *testing.T) {
	svc := closedStoreService(t)
	if err := svc.ValidateVPNName(context.Background(), "new"); err == nil {
		t.Fatal("expected store error")
	}
}

func TestValidateCreateVPNProtocolPreviewEmptyProtocol(t *testing.T) {
	svc, _ := newTestService(t)
	if err := svc.ValidateCreateVPNProtocolPreviewForTest(context.Background(), service.CreateVPNInput{}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateCreateVPNProtocolPreviewUnknownProtocol(t *testing.T) {
	svc, _ := newTestService(t)
	if err := svc.ValidateCreateVPNProtocolPreviewForTest(context.Background(), service.CreateVPNInput{Protocol: "unknown"}); err == nil {
		t.Fatal("expected unknown protocol")
	}
}

func TestValidateCreateVPNDraftFull(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if err := svc.ValidateCreateVPNDraft(ctx, service.CreateVPNInput{
		Name: "new", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{ListenPort: 15010},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateCreateVPNDraftValidateVPNError(t *testing.T) {
	svc, _ := newTestService(t)
	if err := svc.ValidateCreateVPNDraft(context.Background(), service.CreateVPNInput{
		Name: "new", Protocol: "vless", Enabled: true,
		Listen: domain.ListenOptions{ListenPort: 15011},
		VLESS:  service.VLESSCreateOptions{DefaultFlow: "vision", Transport: "grpc", ServerName: "example.com"},
	}); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateCreateVPNWizardStepNameValidation(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{ListenPort: 15012},
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.ValidateCreateVPNWizardStep(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Listen: domain.ListenOptions{ListenPort: 15013},
	}, service.WizardAfterPort); err == nil {
		t.Fatal("expected duplicate name")
	}
}

func TestValidateCreateVPNDraftInputFields(t *testing.T) {
	svc, _ := newTestService(t)
	if err := svc.ValidateCreateVPNDraft(context.Background(), service.CreateVPNInput{
		Protocol: "socks5", HTTPTLS: true, Listen: domain.ListenOptions{ListenPort: 15020},
	}); err == nil {
		t.Fatal("expected input fields error")
	}
}

func TestValidateCreateVPNDraftEmptyListenHost(t *testing.T) {
	svc, _ := newTestService(t)
	if err := svc.ValidateCreateVPNDraft(context.Background(), service.CreateVPNInput{
		Name: "new", Protocol: "socks5", Enabled: true, Listen: domain.ListenOptions{ListenPort: 15021},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateCreateVPNWizardStepInputFields(t *testing.T) {
	svc, _ := newTestService(t)
	if err := svc.ValidateCreateVPNWizardStep(context.Background(), service.CreateVPNInput{
		Protocol: "socks5", HTTPTLS: true,
	}, service.WizardAfterPort); err == nil {
		t.Fatal("expected input fields error")
	}
}

func TestValidateCreateVPNProtocolPreviewListenDefault(t *testing.T) {
	svc, _ := newTestService(t)
	if err := svc.ValidateCreateVPNProtocolPreviewForTest(context.Background(), service.CreateVPNInput{
		Protocol: "socks5", Listen: domain.ListenOptions{ListenPort: 15022},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateCreateVPNDraftDuplicateName(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: false, Listen: domain.ListenOptions{ListenPort: 15030},
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.ValidateCreateVPNDraft(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: true, Listen: domain.ListenOptions{ListenPort: 15031},
	}); err == nil {
		t.Fatal("expected duplicate name")
	}
}

func TestValidateCreateVPNProtocolPreviewValidationError(t *testing.T) {
	svc, _ := newTestService(t)
	if err := svc.ValidateCreateVPNProtocolPreviewForTest(context.Background(), service.CreateVPNInput{
		Protocol: "vless",
		VLESS:    service.VLESSCreateOptions{DefaultFlow: "vision", Transport: "grpc", ServerName: "example.com"},
	}); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateCreateVPNWizardStepPortValidation(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 15003},
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.ValidateCreateVPNWizardStep(ctx, service.CreateVPNInput{
		Name: "other", Protocol: "socks5", Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 15003},
	}, service.WizardAfterPort); err == nil {
		t.Fatal("expected duplicate port")
	}
}

func TestValidateCreateVPNDraftBuildPreviewError(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "m.json"), DevMode: true}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	reg := customRegistry(t, buildFailProtocol{})
	svc := service.NewService(app, st, reg, man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	if err := svc.ValidateCreateVPNDraft(context.Background(), service.CreateVPNInput{
		Name: "x", Protocol: "buildfail", Listen: domain.ListenOptions{ListenPort: 15020},
	}); err == nil {
		t.Fatal("expected preview error")
	}
}

func TestValidateCreateVPNProtocolPreviewValidateErrorNonClient(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "m.json"), DevMode: true}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	reg := customRegistry(t, previewValidateFailProtocol{})
	svc := service.NewService(app, st, reg, man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	if err := svc.ValidateCreateVPNProtocolPreviewForTest(context.Background(), service.CreateVPNInput{
		Name: "x", Protocol: "prevfail", Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 15044},
	}); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateCreateVPNDraftClientValidationIgnored(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "m.json"), DevMode: true}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	reg := customRegistry(t, clientRequiredProtocol{})
	svc := service.NewService(app, st, reg, man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	if err := svc.ValidateCreateVPNDraft(context.Background(), service.CreateVPNInput{
		Name: "new", Protocol: "stub", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 15030},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateCreateVPNDraftValidationError(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "m.json"), DevMode: true}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	reg := customRegistry(t, draftValidateFailProtocol{})
	svc := service.NewService(app, st, reg, man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	if err := svc.ValidateCreateVPNDraft(context.Background(), service.CreateVPNInput{
		Name: "new", Protocol: "draftfail", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 15033},
	}); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateCreateVPNProtocolPreviewBuildError(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "m.json"), DevMode: true}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	reg := customRegistry(t, buildFailProtocol{})
	svc := service.NewService(app, st, reg, man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	if err := svc.ValidateCreateVPNProtocolPreviewForTest(context.Background(), service.CreateVPNInput{
		Protocol: "buildfail", Listen: domain.ListenOptions{ListenPort: 15031},
	}); err == nil {
		t.Fatal("expected build error")
	}
}

func TestValidateCreateVPNProtocolPreviewClientErrorIgnored(t *testing.T) {
	svc, _ := newTestService(t)
	if err := svc.ValidateCreateVPNProtocolPreviewForTest(context.Background(), service.CreateVPNInput{
		Protocol: "socks5", Listen: domain.ListenOptions{ListenPort: 15032},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateCreateVPNWizardStepTransport(t *testing.T) {
	svc, _ := newTestService(t)
	if err := svc.ValidateCreateVPNWizardStep(context.Background(), service.CreateVPNInput{
		Name: "vl", Protocol: "vless", Enabled: true,
		Listen: domain.ListenOptions{ListenPort: 15022},
		VLESS:  service.VLESSCreateOptions{ServerName: "example.com"},
	}, service.WizardAfterTransport); err != nil {
		t.Fatal(err)
	}
}

func TestValidateCreateVPNDraftDefaultListen(t *testing.T) {
	svc, _ := newTestService(t)
	if err := svc.ValidateCreateVPNDraft(context.Background(), service.CreateVPNInput{
		Name: "new", Protocol: "socks5", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateCreateVPNDraftListenPortError(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{Name: "main", Protocol: "socks5", Enabled: true, Listen: domain.ListenOptions{ListenPort: 15041}}); err != nil {
		t.Fatal(err)
	}
	if err := svc.ValidateCreateVPNDraft(ctx, service.CreateVPNInput{Name: "other", Protocol: "socks5", Enabled: true, Listen: domain.ListenOptions{ListenPort: 15041}}); err == nil {
		t.Fatal("expected port error")
	}
}

func TestValidateCreateVPNProtocolPreviewSuccess(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{DataDir: dir, DBPath: filepath.Join(dir, "state.db"), ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "m.json"), DevMode: true}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	reg := customRegistry(t, okProtocol{})
	svc := service.NewService(app, st, reg, man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	if err := svc.ValidateCreateVPNProtocolPreviewForTest(context.Background(), service.CreateVPNInput{
		Name: "ss", Protocol: "stub", Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 15042},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateCreateVPNProtocolPreviewDefaultListen(t *testing.T) {
	svc, _ := newTestService(t)
	if err := svc.ValidateCreateVPNProtocolPreviewForTest(context.Background(), service.CreateVPNInput{
		Protocol: "socks5",
	}); err != nil {
		t.Fatal(err)
	}
}
