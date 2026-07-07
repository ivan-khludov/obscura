package trojan_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/trojan"
)

func TestAdapter_metadata(t *testing.T) {
	a := &trojan.Adapter{}
	if a.Type() != "trojan" {
		t.Fatalf("Type() = %q", a.Type())
	}
	def := a.DefaultListen()
	if def.Listen != "0.0.0.0" || def.ListenPort != 443 {
		t.Fatalf("DefaultListen() = %#v", def)
	}
	fields := a.SupportedListenFields()
	if len(fields) == 0 {
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

func TestValidateVPN_errors(t *testing.T) {
	adapter := &trojan.Adapter{}
	raw := validCertData(t)
	listen := domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443}
	validClient := domain.ClientConfig{Name: "phone", Password: "secret", Enabled: true}
	validVPN := domain.VPNConfig{Name: "main", Tag: "vpn-main", Listen: listen, ProtocolData: raw}

	if err := adapter.ValidateVPN(domain.VPNConfig{Tag: "t", Listen: listen, ProtocolData: raw}, []domain.ClientConfig{validClient}); err == nil {
		t.Fatal("expected name error")
	}
	if err := adapter.ValidateVPN(domain.VPNConfig{Name: "main", Listen: listen, ProtocolData: raw}, []domain.ClientConfig{validClient}); err == nil {
		t.Fatal("expected tag error")
	}
	if err := adapter.ValidateVPN(domain.VPNConfig{Name: "main", Tag: "t", Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 0}, ProtocolData: raw}, []domain.ClientConfig{validClient}); err == nil {
		t.Fatal("expected listen error")
	}
	if err := adapter.ValidateVPN(domain.VPNConfig{Name: "main", Tag: "t", Listen: listen, ProtocolData: []byte("{")}, []domain.ClientConfig{validClient}); err == nil {
		t.Fatal("expected parse error")
	}
	badOpts, _ := trojan.MarshalProtocolData(trojan.ProtocolData{ServerName: "example.com"})
	if err := adapter.ValidateVPN(domain.VPNConfig{Name: "main", Tag: "t", Listen: listen, ProtocolData: badOpts}, []domain.ClientConfig{validClient}); err == nil {
		t.Fatal("expected options error")
	}
	if err := adapter.ValidateVPN(validVPN, []domain.ClientConfig{{Name: "bad", Enabled: true}}); err == nil {
		t.Fatal("expected client validation error")
	}
	if err := adapter.ValidateVPN(validVPN, nil); err == nil {
		t.Fatal("expected no enabled clients error")
	}
}

func TestValidateVPN_disabledClientSkipped(t *testing.T) {
	adapter := &trojan.Adapter{}
	raw := validCertData(t)
	vpn := domain.VPNConfig{
		Name: "main", Tag: "vpn-main",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: raw,
	}
	clients := []domain.ClientConfig{
		{Name: "disabled", Enabled: false},
		{Name: "phone", Password: "secret", Enabled: true},
	}
	if err := adapter.ValidateVPN(vpn, clients); err != nil {
		t.Fatal(err)
	}
}

func TestValidateClient(t *testing.T) {
	adapter := &trojan.Adapter{}
	if err := adapter.ValidateClient(domain.ClientConfig{Password: "p"}); err != nil {
		t.Fatalf("valid client: %v", err)
	}
	if err := adapter.ValidateClient(domain.ClientConfig{Name: "x"}); err == nil || !strings.Contains(err.Error(), "password is required") {
		t.Fatalf("missing password: %v", err)
	}
}

func TestRenderInbound_Golden(t *testing.T) {
	adapter := &trojan.Adapter{}
	vpn := testVPN(t, validCertData(t))
	clients := []domain.ClientConfig{{Name: "phone", Password: "secret", Enabled: true}}
	got, err := adapter.RenderInbound(vpn, clients)
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "../testdata/trojan_inbound.golden.json", got)
}

func TestRenderInbound_MultiplexGolden(t *testing.T) {
	data, err := trojan.MarshalProtocolData(trojan.ProtocolData{
		CertPath: "/etc/obscura/certs/vpn-main.crt", KeyPath: "/etc/obscura/certs/vpn-main.key",
		ServerName: "example.com", ALPN: []string{"h2", "http/1.1"},
		Multiplex: true, MultiplexPadding: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &trojan.Adapter{}
	got, err := adapter.RenderInbound(testVPN(t, data), []domain.ClientConfig{{Name: "phone", Password: "secret", Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "../testdata/trojan_inbound_multiplex.golden.json", got)
}

func TestRenderInbound_WSGolden(t *testing.T) {
	data, err := trojan.MarshalProtocolData(trojan.ProtocolData{
		CertPath: "/etc/obscura/certs/vpn-main.crt", KeyPath: "/etc/obscura/certs/vpn-main.key",
		ServerName: "example.com", ALPN: []string{"http/1.1"},
		TransportType: "ws", TransportWS: &trojan.TransportWS{Path: "/video"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := (&trojan.Adapter{}).RenderInbound(testVPN(t, data), []domain.ClientConfig{{Name: "phone", Password: "secret", Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "../testdata/trojan_inbound_ws.golden.json", got)
}

func TestRenderInbound_FallbackGolden(t *testing.T) {
	data, err := trojan.MarshalProtocolData(trojan.ProtocolData{
		CertPath: "/etc/obscura/certs/vpn-main.crt", KeyPath: "/etc/obscura/certs/vpn-main.key",
		ServerName: "example.com", ALPN: []string{"h2", "http/1.1"},
		FallbackServer: "127.0.0.1", FallbackPort: 8080,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := (&trojan.Adapter{}).RenderInbound(testVPN(t, data), []domain.ClientConfig{{Name: "phone", Password: "secret", Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "../testdata/trojan_inbound_fallback.golden.json", got)
}

func TestRenderInbound_validationError(t *testing.T) {
	_, err := (&trojan.Adapter{}).RenderInbound(domain.VPNConfig{}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRenderInbound_parseErrorAfterValidate(t *testing.T) {
	raw := validCertData(t)
	client := domain.ClientConfig{Name: "phone", Password: "secret", Enabled: true}
	restore := trojan.SetParseProtocolDataHookForTest(func([]byte) (trojan.ProtocolData, error) {
		return trojan.ProtocolData{}, errors.New("parse failed")
	})
	t.Cleanup(restore)
	_, err := (&trojan.Adapter{}).RenderInbound(testVPN(t, raw), []domain.ClientConfig{client})
	if err == nil || !strings.Contains(err.Error(), "parse failed") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestClientURI(t *testing.T) {
	adapter := &trojan.Adapter{}
	vpn := domain.VPNConfig{
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: validCertData(t),
	}
	client := domain.ClientConfig{Name: "phone", Password: "pass", Enabled: true}
	uri, err := adapter.ClientURI(vpn, []domain.ClientConfig{client}, client, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !containsAll(uri, "trojan://", "pass@", "example.com:443", "security=tls", "sni=example.com", "type=tcp", "allowInsecure=1", "#phone") {
		t.Fatalf("unexpected uri: %s", uri)
	}
}

func TestClientURI_allTransports(t *testing.T) {
	adapter := &trojan.Adapter{}
	base := domain.VPNConfig{Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443}}
	client := domain.ClientConfig{Username: "user", Password: "pass", Enabled: true}

	cases := []struct {
		name string
		data trojan.ProtocolData
		want []string
	}{
		{
			name: "ws",
			data: trojan.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
				TransportType: "ws", TransportWS: &trojan.TransportWS{Path: "/p"},
			},
			want: []string{"type=ws", "path=%2Fp"},
		},
		{
			name: "http",
			data: trojan.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
				TransportType: "http", TransportHTTP: &trojan.TransportHTTP{Path: "/h"},
			},
			want: []string{"type=http", "path=%2Fh"},
		},
		{
			name: "httpupgrade",
			data: trojan.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
				TransportType: "httpupgrade", TransportHTTPUpgrade: &trojan.TransportHTTPUpgrade{Path: "/u", Host: "h.example.com"},
			},
			want: []string{"type=httpupgrade", "path=%2Fu", "host=h.example.com"},
		},
		{
			name: "grpc",
			data: trojan.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
				TransportType: "grpc", TransportGRPC: &trojan.TransportGRPC{ServiceName: "svc"},
			},
			want: []string{"type=grpc", "serviceName=svc"},
		},
		{
			name: "multiplex",
			data: trojan.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com", Multiplex: true,
			},
			want: []string{"mux=true"},
		},
		{
			name: "reality no insecure",
			data: trojan.ProtocolData{
				RealityEnabled: true, RealityPrivateKey: "k", RealityShortIDs: []string{"ab"},
				RealityHandshakeServer: "www.bing.com",
			},
			want: []string{"type=tcp"},
		},
		{
			name: "username fragment",
			data: trojan.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
			},
			want: []string{"#user"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := trojan.MarshalProtocolData(tc.data)
			if err != nil {
				t.Fatal(err)
			}
			vpn := base
			vpn.ProtocolData = raw
			c := client
			if tc.name == "username fragment" {
				c.Name = ""
			} else {
				c.Name = "phone"
			}
			uri, err := adapter.ClientURI(vpn, nil, c, "example.com")
			if err != nil {
				t.Fatal(err)
			}
			if tc.name == "reality no insecure" && strings.Contains(uri, "allowInsecure=1") {
				t.Fatalf("reality should not set allowInsecure: %s", uri)
			}
			if !containsAll(uri, tc.want...) {
				t.Fatalf("unexpected uri: %s", uri)
			}
		})
	}
}

func TestClientURI_errors(t *testing.T) {
	adapter := &trojan.Adapter{}
	vpn := domain.VPNConfig{
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: []byte(`{`),
	}
	client := domain.ClientConfig{Name: "phone", Password: "pass", Enabled: true}
	if _, err := adapter.ClientURI(vpn, nil, domain.ClientConfig{}, "host"); err == nil {
		t.Fatal("expected validate client error")
	}
	if _, err := adapter.ClientURI(vpn, nil, client, "host"); err == nil {
		t.Fatal("expected parse protocol data error")
	}
}

func TestClientQRContent(t *testing.T) {
	adapter := &trojan.Adapter{}
	vpn := domain.VPNConfig{
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: validCertData(t),
	}
	client := domain.ClientConfig{Name: "phone", Password: "pass", Enabled: true}
	qr, err := adapter.ClientQRContent(vpn, []domain.ClientConfig{client}, client, "example.com")
	if err != nil || !strings.HasPrefix(qr, "trojan://") {
		t.Fatalf("ClientQRContent() = %q, %v", qr, err)
	}
}

func TestValidateVPN_RequiresClient(t *testing.T) {
	adapter := &trojan.Adapter{}
	vpn := domain.VPNConfig{
		Name: "main", Tag: "vpn-main",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: validCertData(t),
	}
	if err := adapter.ValidateVPN(vpn, nil); err == nil {
		t.Fatal("expected error without clients")
	}
}

func TestRenderInbound_FallbackForALPN(t *testing.T) {
	data, err := trojan.MarshalProtocolData(trojan.ProtocolData{
		CertPath: "/etc/obscura/certs/vpn-main.crt", KeyPath: "/etc/obscura/certs/vpn-main.key",
		ServerName: "example.com",
		FallbackForALPN: map[string]trojan.FallbackTarget{
			"h2": {Server: "127.0.0.1", ServerPort: 9090},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	vpn := testVPN(t, data)
	vpn.Listen.BindInterface = "eth0"
	got, err := (&trojan.Adapter{}).RenderInbound(vpn, []domain.ClientConfig{{Name: "phone", Password: "secret", Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	if got["fallback_for_alpn"] == nil {
		t.Fatalf("expected fallback_for_alpn: %#v", got)
	}
	if got["bind_interface"] != "eth0" {
		t.Fatalf("expected bind_interface: %#v", got)
	}
}

func TestNeedsInitialClient(t *testing.T) {
	if !(&trojan.Adapter{}).NeedsInitialClient(domain.VPNConfig{}) {
		t.Fatal("expected true")
	}
}
