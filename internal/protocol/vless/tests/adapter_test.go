package vless_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/vless"
)

func TestAdapter_metadata(t *testing.T) {
	a := &vless.Adapter{}
	if a.Type() != "vless" {
		t.Fatalf("Type() = %q", a.Type())
	}
	def := a.DefaultListen()
	if def.Listen != "0.0.0.0" || def.ListenPort != 443 {
		t.Fatalf("DefaultListen() = %#v", def)
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

func TestRenderInbound_Golden(t *testing.T) {
	clientUUID := uuid.NewString()
	data, err := vless.MarshalProtocolData(vless.ProtocolData{
		CertPath:   "/etc/obscura/certs/vpn-main.crt",
		KeyPath:    "/etc/obscura/certs/vpn-main.key",
		ServerName: "example.com",
		ALPN:       []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &vless.Adapter{}
	vpn := domain.VPNConfig{
		Name: "main", Protocol: "vless", Tag: "vpn-main", Enabled: true,
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: data,
	}
	clients := []domain.ClientConfig{
		{Name: "phone", Password: clientUUID, Enabled: true},
	}
	got, err := adapter.RenderInbound(vpn, clients)
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "../testdata/vless_inbound.golden.json", got)
}

func TestRenderInbound_multiplexAndTransport(t *testing.T) {
	data, err := vless.MarshalProtocolData(vless.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
		Multiplex: true, MultiplexPadding: true,
		TransportType: "ws", TransportWS: &vless.TransportWS{Path: "/ws"},
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &vless.Adapter{}
	vpn := domain.VPNConfig{
		Name: "main", Tag: "vpn-main",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: data,
	}
	got, err := adapter.RenderInbound(vpn, []domain.ClientConfig{
		{Name: "phone", Password: uuid.NewString(), Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got["multiplex"] == nil || got["transport"] == nil {
		t.Fatalf("expected multiplex and transport: %#v", got)
	}
}

func TestRenderInbound_errors(t *testing.T) {
	adapter := &vless.Adapter{}
	_, err := adapter.RenderInbound(domain.VPNConfig{}, nil)
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestRenderInbound_usersError(t *testing.T) {
	vpn, client := validCertVPN(t)
	restore := vless.SetParseProtocolDataHookForTest(parseHookFlowConflictOnSecond())
	defer restore()
	adapter := &vless.Adapter{}
	_, err := adapter.RenderInbound(vpn, []domain.ClientConfig{client})
	if err == nil || !strings.Contains(err.Error(), "direct transport") {
		t.Fatalf("expected users error, got %v", err)
	}
}

func TestRenderInbound_parseError(t *testing.T) {
	vpn, client := validCertVPN(t)
	restore := vless.SetParseProtocolDataHookForTest(parseHookFailOnSecond())
	defer restore()
	_, err := (&vless.Adapter{}).RenderInbound(vpn, []domain.ClientConfig{client})
	if err == nil || err.Error() != "parse failed" {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestValidateVPN(t *testing.T) {
	validData, _ := vless.MarshalProtocolData(vless.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
	})
	validVPN := domain.VPNConfig{
		Name: "main", Tag: "vpn-main",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: validData,
	}
	validClient := domain.ClientConfig{Name: "phone", Password: uuid.NewString(), Enabled: true}
	adapter := &vless.Adapter{}

	if err := adapter.ValidateVPN(validVPN, []domain.ClientConfig{validClient, {Name: "off", Password: uuid.NewString(), Enabled: false}}); err != nil {
		t.Fatalf("valid vpn with disabled client: %v", err)
	}
	if err := adapter.ValidateVPN(domain.VPNConfig{Tag: "t", ProtocolData: validData}, nil); err == nil {
		t.Fatal("expected name required")
	}
	if err := adapter.ValidateVPN(domain.VPNConfig{Name: "n", ProtocolData: validData}, nil); err == nil {
		t.Fatal("expected tag required")
	}
	if err := adapter.ValidateVPN(domain.VPNConfig{
		Name: "n", Tag: "t", Listen: domain.ListenOptions{ListenPort: -1}, ProtocolData: validData,
	}, nil); err == nil {
		t.Fatal("expected listen error")
	}
	if err := adapter.ValidateVPN(domain.VPNConfig{
		Name: "n", Tag: "t", Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: []byte(`{`),
	}, nil); err == nil {
		t.Fatal("expected parse error")
	}
	if err := adapter.ValidateVPN(domain.VPNConfig{
		Name: "n", Tag: "t", Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: []byte(`{"server_name":"example.com"}`),
	}, nil); err == nil {
		t.Fatal("expected options validation error")
	}
	if err := adapter.ValidateVPN(validVPN, nil); err == nil || !strings.Contains(err.Error(), "at least one enabled client") {
		t.Fatalf("no clients error = %v", err)
	}
	badClient := domain.ClientConfig{Name: "bad", Password: "not-uuid", Enabled: true}
	if err := adapter.ValidateVPN(validVPN, []domain.ClientConfig{badClient}); err == nil {
		t.Fatal("expected client validation error")
	}
	flowVPN, flowClient := flowConflictVPN(t)
	if err := adapter.ValidateVPN(flowVPN, []domain.ClientConfig{flowClient}); err == nil || !strings.Contains(err.Error(), "direct transport") {
		t.Fatalf("flow conflict error = %v", err)
	}
}

func TestValidateClient(t *testing.T) {
	adapter := &vless.Adapter{}
	if err := adapter.ValidateClient(domain.ClientConfig{}); err == nil {
		t.Fatal("expected uuid required")
	}
	if err := adapter.ValidateClient(domain.ClientConfig{Password: "not-uuid"}); err == nil {
		t.Fatal("expected invalid uuid")
	}
	if err := adapter.ValidateClient(domain.ClientConfig{Password: uuid.NewString()}); err != nil {
		t.Fatal(err)
	}
	if err := adapter.ValidateClient(domain.ClientConfig{
		Password: uuid.NewString(), Username: vless.FlowVision,
	}); err != nil {
		t.Fatal(err)
	}
	if err := adapter.ValidateClient(domain.ClientConfig{
		Password: uuid.NewString(), Username: "bad-flow",
	}); err == nil {
		t.Fatal("expected flow validation error")
	}
}

func TestClientURI(t *testing.T) {
	clientUUID := uuid.NewString()
	data, err := vless.MarshalProtocolData(vless.ProtocolData{
		CertPath:   "/etc/obscura/certs/vpn-main.crt",
		KeyPath:    "/etc/obscura/certs/vpn-main.key",
		ServerName: "example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &vless.Adapter{}
	vpn := domain.VPNConfig{
		Name: "main", Protocol: "vless", Tag: "vpn-main", Enabled: true,
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: data,
	}
	client := domain.ClientConfig{Name: "phone", Password: clientUUID, Enabled: true}
	uri, err := adapter.ClientURI(vpn, []domain.ClientConfig{client}, client, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(uri) < 8 || uri[:8] != "vless://" {
		t.Fatalf("unexpected uri: %q", uri)
	}
	if !strings.Contains(uri, "allowInsecure=1") {
		t.Fatalf("expected allowInsecure in uri, got %q", uri)
	}
}

func TestClientURI_RealityNoInsecure(t *testing.T) {
	clientUUID := uuid.NewString()
	data, err := vless.MarshalProtocolData(vless.ProtocolData{
		RealityEnabled:   true,
		RealityPublicKey: "pub",
		RealityShortIDs:  []string{"abcd"},
		ServerName:       "example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &vless.Adapter{}
	vpn := domain.VPNConfig{
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: data,
	}
	client := domain.ClientConfig{Name: "phone", Password: clientUUID, Enabled: true}
	uri, err := adapter.ClientURI(vpn, []domain.ClientConfig{client}, client, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(uri, "allowInsecure") {
		t.Fatalf("reality uri must not include allowInsecure, got %q", uri)
	}
	if !strings.Contains(uri, "fp=chrome") {
		t.Fatalf("expected fp=chrome in reality uri, got %q", uri)
	}
}

func TestClientURI_RealityFingerprint(t *testing.T) {
	clientUUID := uuid.NewString()
	data, err := vless.MarshalProtocolData(vless.ProtocolData{
		RealityEnabled:         true,
		RealityPublicKey:       "pub",
		RealityShortIDs:        []string{"abcd"},
		RealityUTLSFingerprint: "firefox",
		ServerName:             "example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &vless.Adapter{}
	vpn := domain.VPNConfig{
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: data,
	}
	client := domain.ClientConfig{Name: "phone", Password: clientUUID, Enabled: true}
	uri, err := adapter.ClientURI(vpn, []domain.ClientConfig{client}, client, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(uri, "fp=firefox") {
		t.Fatalf("expected fp=firefox in reality uri, got %q", uri)
	}
}

func TestClientURI_errors(t *testing.T) {
	adapter := &vless.Adapter{}
	vpn := domain.VPNConfig{
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: []byte(`{`),
	}
	client := domain.ClientConfig{Name: "phone", Password: uuid.NewString(), Enabled: true}
	if _, err := adapter.ClientURI(vpn, nil, domain.ClientConfig{}, "host"); err == nil {
		t.Fatal("expected validate client error")
	}
	if _, err := adapter.ClientURI(vpn, nil, client, "host"); err == nil {
		t.Fatal("expected parse protocol data error")
	}
}

func TestClientQRContent(t *testing.T) {
	data, err := vless.MarshalProtocolData(vless.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &vless.Adapter{}
	vpn := domain.VPNConfig{
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: data,
	}
	client := domain.ClientConfig{Name: "phone", Password: uuid.NewString(), Enabled: true}
	qr, err := adapter.ClientQRContent(vpn, []domain.ClientConfig{client}, client, "example.com")
	if err != nil || !strings.HasPrefix(qr, "vless://") {
		t.Fatalf("ClientQRContent() = %q, %v", qr, err)
	}
}
