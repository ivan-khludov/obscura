package service_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/ivan-khludov/obscura/internal/config"
	"github.com/ivan-khludov/obscura/internal/doctor"
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/fallback"
	"github.com/ivan-khludov/obscura/internal/firewall"
	"github.com/ivan-khludov/obscura/internal/manifest"
	"github.com/ivan-khludov/obscura/internal/protocol/trojan"
	"github.com/ivan-khludov/obscura/internal/runtime"
	"github.com/ivan-khludov/obscura/internal/service"
	"github.com/ivan-khludov/obscura/internal/singboxcheck"
	"github.com/ivan-khludov/obscura/internal/systemd"
)

func TestStatus(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 13001},
	}); err != nil {
		t.Fatal(err)
	}
	st, err := svc.Status(ctx)
	if err != nil || st.VPNCount != 1 || st.ClientCount < 1 {
		t.Fatalf("status: %#v err=%v", st, err)
	}
}

func TestDoctor(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	results := svc.Doctor(ctx)
	if len(results) == 0 {
		t.Fatal("expected doctor results")
	}
}

func TestRequireRootForBootstrapDev(t *testing.T) {
	svc, _ := newTestService(t)
	if err := svc.RequireRootForBootstrap(); err != nil {
		t.Fatal(err)
	}
}

func TestRequireRootForBootstrapProd(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	svc.SetRootCheckForTest(func() bool { return false })
	if err := svc.RequireRootForBootstrap(); err == nil {
		t.Fatal("expected root error")
	}
}

func TestNeedsFallbackStub(t *testing.T) {
	svc, _ := newTestService(t)
	if svc.NeedsFallbackStubForTest(context.Background()) {
		t.Fatal("expected no fallback stub needed")
	}
}

func TestCheckFallbackStub(t *testing.T) {
	svc, _ := newTestService(t)
	result := svc.CheckFallbackStubForTest(context.Background())
	if result.Name != "fallback_stub" {
		t.Fatalf("result=%#v", result)
	}
}

func TestNeedsFallbackStubTrue(t *testing.T) {
	svc, st := newTestService(t)
	ctx := context.Background()
	raw, err := trojan.MarshalProtocolData(trojan.ProtocolData{
		FallbackServer: fallback.DefaultServer,
		FallbackPort:   fallback.DefaultPort,
	})
	if err != nil {
		t.Fatal(err)
	}
	vpn := &domain.VPN{
		Name: "tr", Protocol: "trojan", Tag: "vpn-tr", Enabled: true,
		Listen: domain.ListenOptions{ListenPort: 443}, ProtocolData: raw,
	}
	if err := st.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	if !svc.NeedsFallbackStubForTest(ctx) {
		t.Fatal("expected fallback stub needed")
	}
	results := svc.Doctor(ctx)
	found := false
	for _, r := range results {
		if r.Name == "fallback_stub" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected fallback_stub doctor check")
	}
}

func TestCheckFallbackStubActive(t *testing.T) {
	svc, _ := newTestService(t)
	svc.SetFallbackActiveForTest(func(context.Context) (bool, error) { return true, nil })
	got := svc.CheckFallbackStubForTest(context.Background())
	if got.Status != doctor.StatusOK {
		t.Fatalf("status=%#v", got)
	}
}

func TestCheckFallbackStubError(t *testing.T) {
	svc, _ := newTestService(t)
	svc.SetFallbackActiveForTest(func(context.Context) (bool, error) { return false, fmt.Errorf("boom") })
	got := svc.CheckFallbackStubForTest(context.Background())
	if got.Status != doctor.StatusFail {
		t.Fatalf("status=%#v", got)
	}
}

func TestStatusClosedStore(t *testing.T) {
	svc := closedStoreService(t)
	if _, err := svc.Status(context.Background()); err == nil {
		t.Fatal("expected store error")
	}
}

func TestNeedsFallbackStubClosedStore(t *testing.T) {
	svc := closedStoreService(t)
	if svc.NeedsFallbackStubForTest(context.Background()) {
		t.Fatal("expected false on store error")
	}
}

func TestStatusListClientsError(t *testing.T) {
	svc, st := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: false,
		Listen: domain.ListenOptions{ListenPort: 13002},
	}); err != nil {
		t.Fatal(err)
	}
	fs := wrapFaultStore(st)
	fs.listClientsErr = fmt.Errorf("list failed")
	svc.SetStoreForTest(fs)
	if _, err := svc.Status(ctx); err == nil {
		t.Fatal("expected status error")
	}
}
