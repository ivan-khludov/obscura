package render_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/render"
	"github.com/ivan-khludov/obscura/internal/runtime"
	"github.com/ivan-khludov/obscura/internal/store"
)

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	return s
}

func TestNewRenderer(t *testing.T) {
	s := openTestStore(t)
	if render.NewRenderer(s, runtime.NewProtocolRegistry()) == nil {
		t.Fatal("expected non-nil renderer")
	}
}

func TestRenderer_SkipsClientlessVPN(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	reg := runtime.NewProtocolRegistry()
	vpn := &domain.VPN{
		Name: "my", Protocol: "socks5", Tag: "vpn-my", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080},
	}
	if err := s.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	r := render.NewRenderer(s, reg)
	raw, err := r.Render(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	inbounds, ok := cfg["inbounds"].([]any)
	if !ok || len(inbounds) != 0 {
		t.Fatalf("expected 0 inbounds for clientless vpn, got %#v", cfg["inbounds"])
	}
}

func TestRenderer_Socks5Inbound(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	reg := runtime.NewProtocolRegistry()
	vpn := &domain.VPN{
		Name: "main", Protocol: "socks5", Tag: "vpn-main", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080},
	}
	if err := s.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	client := &domain.Client{
		VPNID: vpn.ID, Name: "phone", Username: "phone", Password: "secret", Enabled: true,
	}
	if err := s.CreateClient(ctx, client); err != nil {
		t.Fatal(err)
	}
	r := render.NewRenderer(s, reg)
	raw, err := r.Render(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	inbounds, ok := cfg["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		t.Fatalf("expected 1 inbound, got %#v", cfg["inbounds"])
	}
}

func TestRenderer_FullAdapterPaths(t *testing.T) {
	ctx := context.Background()
	reg := protocol.NewRegistry()
	reg.Register(&testAdapter{
		proto:       "full-test",
		usesInbound: true,
		extras:      []map[string]any{{"type": "shadowtls", "tag": "extra"}},
		inbound:     map[string]any{"type": "socks", "tag": "vpn-full"},
		endpoints:   []map[string]any{{"type": "wireguard", "tag": "wg-endpoint"}},
		rules:       []map[string]any{{"inbound": "vpn-full", "outbound": "direct", "network": "udp"}},
	})
	vpn, client := vpnWithClient(1, "full", "full-test")
	st := &stubStore{
		vpns:    []domain.VPN{vpn},
		clients: map[int64][]domain.Client{vpn.ID: {client}},
	}
	raw, err := render.NewRenderer(st, reg).Render(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var cfg render.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Inbounds) != 2 {
		t.Fatalf("expected extra + primary inbound, got %#v", cfg.Inbounds)
	}
	if len(cfg.Endpoints) != 1 {
		t.Fatalf("expected endpoints, got %#v", cfg.Endpoints)
	}
	if len(cfg.Route.Rules) != 1 || cfg.Route.Rules[0]["network"] != "udp" {
		t.Fatalf("unexpected route rules: %#v", cfg.Route.Rules)
	}
}

func TestRenderer_RouteRuleMappingPreservesExtensionFields(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	reg := protocol.NewRegistry()
	reg.Register(&testAdapter{
		proto:       "route-test",
		usesInbound: false,
		rules:       []map[string]any{{"inbound": "vpn-route", "outbound": "direct", "network": "udp"}},
		inbound:     map[string]any{"type": "socks", "tag": "vpn-route"},
	})
	vpn := &domain.VPN{
		Name: "route", Protocol: "route-test", Tag: "vpn-route", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 9000},
	}
	if err := s.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	client := &domain.Client{
		VPNID: vpn.ID, Name: "phone", Username: "phone", Password: "secret", Enabled: true,
	}
	if err := s.CreateClient(ctx, client); err != nil {
		t.Fatal(err)
	}
	raw, err := render.NewRenderer(s, reg).Render(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"network"`) {
		t.Fatalf("expected extension route fields to be preserved, got %s", string(raw))
	}
	var cfg render.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Route.Rules) != 1 {
		t.Fatalf("expected one route rule, got %#v", cfg.Route.Rules)
	}
	if cfg.Route.Rules[0]["inbound"] != "vpn-route" || cfg.Route.Rules[0]["outbound"] != "direct" {
		t.Fatalf("unexpected route rule: %#v", cfg.Route.Rules[0])
	}
}

func TestRenderer_Errors(t *testing.T) {
	ctx := context.Background()

	t.Run("list enabled vpns", func(t *testing.T) {
		st := &stubStore{listEnabledErr: errStub}
		_, err := render.NewRenderer(st, protocol.NewRegistry()).Render(ctx)
		if err == nil || !strings.Contains(err.Error(), "list vpns") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("unknown protocol", func(t *testing.T) {
		vpn, client := vpnWithClient(1, "bad", "missing")
		st := &stubStore{
			vpns:    []domain.VPN{vpn},
			clients: map[int64][]domain.Client{vpn.ID: {client}},
		}
		_, err := render.NewRenderer(st, protocol.NewRegistry()).Render(ctx)
		if err == nil {
			t.Fatal("expected unknown protocol error")
		}
	})

	t.Run("list clients", func(t *testing.T) {
		vpn, client := vpnWithClient(1, "main", "full-test")
		st := &stubStore{
			vpns:             []domain.VPN{vpn},
			clients:          map[int64][]domain.Client{vpn.ID: {client}},
			listClientsErr:   errStub,
			listClientsVPNID: vpn.ID,
		}
		reg := protocol.NewRegistry()
		reg.Register(&testAdapter{proto: "full-test"})
		_, err := render.NewRenderer(st, reg).Render(ctx)
		if err == nil || !strings.Contains(err.Error(), "list clients") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("additional inbounds", func(t *testing.T) {
		vpn, client := vpnWithClient(1, "main", "full-test")
		st := &stubStore{
			vpns:    []domain.VPN{vpn},
			clients: map[int64][]domain.Client{vpn.ID: {client}},
		}
		reg := protocol.NewRegistry()
		reg.Register(&testAdapter{proto: "full-test", extrasErr: errStub})
		_, err := render.NewRenderer(st, reg).Render(ctx)
		if err == nil || !strings.Contains(err.Error(), "extra inbounds") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("render inbound", func(t *testing.T) {
		vpn, client := vpnWithClient(1, "main", "full-test")
		st := &stubStore{
			vpns:    []domain.VPN{vpn},
			clients: map[int64][]domain.Client{vpn.ID: {client}},
		}
		reg := protocol.NewRegistry()
		reg.Register(&testAdapter{proto: "full-test", usesInbound: true, inboundErr: errStub})
		_, err := render.NewRenderer(st, reg).Render(ctx)
		if err == nil || !strings.Contains(err.Error(), "render vpn") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("render endpoints", func(t *testing.T) {
		vpn, client := vpnWithClient(1, "main", "full-test")
		st := &stubStore{
			vpns:    []domain.VPN{vpn},
			clients: map[int64][]domain.Client{vpn.ID: {client}},
		}
		reg := protocol.NewRegistry()
		reg.Register(&testAdapter{proto: "full-test", endpointsErr: errStub})
		_, err := render.NewRenderer(st, reg).Render(ctx)
		if err == nil || !strings.Contains(err.Error(), "render endpoints") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("route extensions", func(t *testing.T) {
		vpn, client := vpnWithClient(1, "main", "full-test")
		st := &stubStore{
			vpns:    []domain.VPN{vpn},
			clients: map[int64][]domain.Client{vpn.ID: {client}},
		}
		reg := protocol.NewRegistry()
		reg.Register(&testAdapter{proto: "full-test", rulesErr: errStub})
		_, err := render.NewRenderer(st, reg).Render(ctx)
		if err == nil || !strings.Contains(err.Error(), "route extensions") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestRenderer_ClosedStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "closed.db")
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = render.NewRenderer(s, runtime.NewProtocolRegistry()).Render(context.Background())
	if err == nil {
		t.Fatal("expected render error on closed store")
	}
}
