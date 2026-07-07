package httpproxy_test

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/httpproxy"
)

func TestAdapter_metadata(t *testing.T) {
	a := &httpproxy.Adapter{}
	if a.Type() != "http" {
		t.Fatalf("Type() = %q", a.Type())
	}
	if a.DefaultListen().ListenPort != 8080 {
		t.Fatalf("DefaultListen() = %#v", a.DefaultListen())
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
}

func TestParseProtocolData(t *testing.T) {
	data, err := httpproxy.ParseProtocolData(nil)
	if err != nil || data.TLS {
		t.Fatalf("ParseProtocolData(nil) = %#v, %v", data, err)
	}
	_, err = httpproxy.ParseProtocolData([]byte("{"))
	if err == nil || !strings.Contains(err.Error(), "parse http protocol data") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRenderInbound_Golden(t *testing.T) {
	adapter := &httpproxy.Adapter{}
	vpn := domain.VPNConfig{
		Name: "main", Protocol: "http", Tag: "vpn-main", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8080},
	}
	clients := []domain.ClientConfig{
		{Name: "phone", Username: "phone", Password: "secret", Enabled: true},
	}
	got, err := adapter.RenderInbound(vpn, clients)
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "../testdata/http_inbound.golden.json", got)
}

func TestRenderInbound_TLSGolden(t *testing.T) {
	adapter := &httpproxy.Adapter{}
	data, err := httpproxy.MarshalProtocolData(httpproxy.ProtocolData{
		TLS: true, CertPath: "/etc/obscura/certs/vpn-main.crt", KeyPath: "/etc/obscura/certs/vpn-main.key",
	})
	if err != nil {
		t.Fatal(err)
	}
	vpn := domain.VPNConfig{
		Name: "main", Protocol: "http", Tag: "vpn-main", Enabled: true,
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8443},
		ProtocolData: data,
	}
	clients := []domain.ClientConfig{
		{Name: "phone", Username: "phone", Password: "secret", Enabled: true},
	}
	got, err := adapter.RenderInbound(vpn, clients)
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "../testdata/http_inbound_tls.golden.json", got)
}

func TestClientURI(t *testing.T) {
	adapter := &httpproxy.Adapter{}
	vpn := domain.VPNConfig{
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8080},
	}
	client := domain.ClientConfig{Username: "user", Password: "pass", Enabled: true}
	uri, err := adapter.ClientURI(vpn, []domain.ClientConfig{client}, client, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if uri != "http://user:pass@example.com:8080" {
		t.Fatalf("unexpected uri: %s", uri)
	}
}

func TestClientURI_TLS(t *testing.T) {
	adapter := &httpproxy.Adapter{}
	data, err := httpproxy.MarshalProtocolData(httpproxy.ProtocolData{TLS: true})
	if err != nil {
		t.Fatal(err)
	}
	vpn := domain.VPNConfig{
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8443},
		ProtocolData: data,
	}
	client := domain.ClientConfig{Username: "user", Password: "pass", Enabled: true}
	uri, err := adapter.ClientURI(vpn, []domain.ClientConfig{client}, client, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if uri != "https://user:pass@example.com:8443" {
		t.Fatalf("unexpected uri: %s", uri)
	}
}

func TestClientURI_errors(t *testing.T) {
	adapter := &httpproxy.Adapter{}
	_, err := adapter.ClientURI(domain.VPNConfig{ProtocolData: []byte("{")}, nil, domain.ClientConfig{Username: "u", Password: "p"}, "host")
	if err == nil {
		t.Fatal("expected parse error")
	}
	_, err = adapter.ClientURI(domain.VPNConfig{}, nil, domain.ClientConfig{}, "host")
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestClientQRContent(t *testing.T) {
	adapter := &httpproxy.Adapter{}
	vpn := domain.VPNConfig{
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8080},
	}
	client := domain.ClientConfig{Username: "user", Password: "pass", Enabled: true}
	qr, err := adapter.ClientQRContent(vpn, []domain.ClientConfig{client}, client, "example.com")
	if err != nil || !strings.HasPrefix(qr, "http://") {
		t.Fatalf("ClientQRContent() = %q, %v", qr, err)
	}
}

func TestValidateVPN_errors(t *testing.T) {
	adapter := &httpproxy.Adapter{}
	listen := domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8080}
	client := domain.ClientConfig{Username: "u", Password: "p", Enabled: true}
	if err := adapter.ValidateVPN(domain.VPNConfig{Tag: "t", Listen: listen}, []domain.ClientConfig{client}); err == nil {
		t.Fatal("expected name error")
	}
	if err := adapter.ValidateVPN(domain.VPNConfig{Name: "n", Listen: listen}, []domain.ClientConfig{client}); err == nil {
		t.Fatal("expected tag error")
	}
	tlsData, _ := httpproxy.MarshalProtocolData(httpproxy.ProtocolData{TLS: true})
	if err := adapter.ValidateVPN(domain.VPNConfig{Name: "n", Tag: "t", Listen: listen, ProtocolData: tlsData}, []domain.ClientConfig{client}); err == nil {
		t.Fatal("expected tls cert error")
	}
	badData := []byte("{")
	if err := adapter.ValidateVPN(domain.VPNConfig{Name: "n", Tag: "t", Listen: listen, ProtocolData: badData}, []domain.ClientConfig{client}); err == nil {
		t.Fatal("expected parse error")
	}
	if err := adapter.ValidateVPN(domain.VPNConfig{Name: "n", Tag: "t", Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 0}}, []domain.ClientConfig{client}); err == nil {
		t.Fatal("expected listen error")
	}
	if err := adapter.ValidateVPN(domain.VPNConfig{Name: "n", Tag: "t", Listen: listen}, nil); err == nil {
		t.Fatal("expected client error")
	}
}

func TestRenderInbound_parseError(t *testing.T) {
	adapter := &httpproxy.Adapter{}
	data, _ := httpproxy.MarshalProtocolData(httpproxy.ProtocolData{})
	vpn := domain.VPNConfig{
		Name: "main", Tag: "vpn-main",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8080},
		ProtocolData: data,
	}
	clients := []domain.ClientConfig{{Username: "u", Password: "p", Enabled: true}}
	reset := httpproxy.SetParseProtocolDataHookForTest(func([]byte) (httpproxy.ProtocolData, error) {
		return httpproxy.ProtocolData{}, errors.New("parse failed")
	})
	defer reset()
	_, err := adapter.RenderInbound(vpn, clients)
	if err == nil || !strings.Contains(err.Error(), "parse failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRenderInbound_validationError(t *testing.T) {
	adapter := &httpproxy.Adapter{}
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
