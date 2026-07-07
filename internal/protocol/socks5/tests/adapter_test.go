package socks5_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/socks5"
)

func TestAdapter_metadata(t *testing.T) {
	a := &socks5.Adapter{}
	if a.Type() != "socks5" {
		t.Fatalf("Type() = %q", a.Type())
	}
	if a.DefaultListen().ListenPort == 0 {
		t.Fatal("expected default listen port")
	}
	if len(a.SupportedListenFields()) == 0 {
		t.Fatal("expected listen fields")
	}
	if !a.UsesInbound() {
		t.Fatal("expected UsesInbound true")
	}
	if len(a.FirewallProtos()) == 0 {
		t.Fatal("expected firewall protos")
	}
	re, err := a.RouteExtensions(domain.VPNConfig{})
	if err != nil || re != nil {
		t.Fatalf("RouteExtensions() = %v, %v", re, err)
	}
	ai, err := a.AdditionalInbounds(domain.VPNConfig{}, nil)
	if err != nil || ai != nil {
		t.Fatalf("AdditionalInbounds() = %v, %v", ai, err)
	}
	ep, err := a.RenderEndpoints(domain.VPNConfig{}, nil)
	if err != nil || ep != nil {
		t.Fatalf("RenderEndpoints() = %v, %v", ep, err)
	}
	raw, err := socks5.MarshalProtocolData(socks5.ProtocolData{})
	if err != nil || string(raw) != "{}" {
		t.Fatalf("MarshalProtocolData() = %q, %v", raw, err)
	}
}

func TestRenderInbound_Golden(t *testing.T) {
	adapter := &socks5.Adapter{}
	vpn := domain.VPNConfig{
		Name: "main", Protocol: "socks5", Tag: "vpn-main", Enabled: true,
		Listen: domain.ListenOptions{
			Listen: "0.0.0.0", ListenPort: 1080, TCPFastOpen: true, TCPKeepAlive: "5m",
		},
	}
	clients := []domain.ClientConfig{
		{Name: "phone", Username: "phone", Password: "secret", Enabled: true},
	}
	got, err := adapter.RenderInbound(vpn, clients)
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "../testdata/socks5_inbound.golden.json", got)
}

func TestClientURI(t *testing.T) {
	adapter := &socks5.Adapter{}
	vpn := domain.VPNConfig{
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080},
	}
	client := domain.ClientConfig{Username: "user", Password: "pass", Enabled: true}
	uri, err := adapter.ClientURI(vpn, []domain.ClientConfig{client}, client, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if uri != "socks5://user:pass@example.com:1080" {
		t.Fatalf("unexpected uri: %s", uri)
	}
}

func TestClientURI_invalidClient(t *testing.T) {
	adapter := &socks5.Adapter{}
	_, err := adapter.ClientURI(domain.VPNConfig{}, nil, domain.ClientConfig{}, "host")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClientQRContent(t *testing.T) {
	adapter := &socks5.Adapter{}
	vpn := domain.VPNConfig{
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080},
	}
	client := domain.ClientConfig{Username: "user", Password: "pass", Enabled: true}
	qr, err := adapter.ClientQRContent(vpn, []domain.ClientConfig{client}, client, "example.com")
	if err != nil || !strings.HasPrefix(qr, "socks5://") {
		t.Fatalf("ClientQRContent() = %q, %v", qr, err)
	}
}

func TestValidateVPN_errors(t *testing.T) {
	adapter := &socks5.Adapter{}
	listen := domain.DefaultListenOptions()
	client := domain.ClientConfig{Username: "u", Password: "p", Enabled: true}
	if err := adapter.ValidateVPN(domain.VPNConfig{Tag: "t", Listen: listen}, []domain.ClientConfig{client}); err == nil {
		t.Fatal("expected name error")
	}
	if err := adapter.ValidateVPN(domain.VPNConfig{Name: "n", Listen: listen}, []domain.ClientConfig{client}); err == nil {
		t.Fatal("expected tag error")
	}
	if err := adapter.ValidateVPN(domain.VPNConfig{Name: "n", Tag: "t", Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 0}}, []domain.ClientConfig{client}); err == nil {
		t.Fatal("expected listen error")
	}
	if err := adapter.ValidateVPN(domain.VPNConfig{Name: "n", Tag: "t", Listen: listen}, nil); err == nil {
		t.Fatal("expected client error")
	}
}

func TestValidateClient(t *testing.T) {
	adapter := &socks5.Adapter{}
	if err := adapter.ValidateClient(domain.ClientConfig{Username: "u", Password: "p"}); err != nil {
		t.Fatal(err)
	}
	if err := adapter.ValidateClient(domain.ClientConfig{Password: "p"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestRenderInbound_validationError(t *testing.T) {
	adapter := &socks5.Adapter{}
	_, err := adapter.RenderInbound(domain.VPNConfig{}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func assertGolden(t *testing.T, golden string, got map[string]any) {
	t.Helper()
	raw, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(golden, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden: %v (run with UPDATE_GOLDEN=1)", err)
	}
	var gotMap, wantMap map[string]any
	if err := json.Unmarshal(raw, &gotMap); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(want, &wantMap); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(wantMap, gotMap); diff != "" {
		t.Fatalf("golden mismatch (-want +got):\n%s", diff)
	}
}
