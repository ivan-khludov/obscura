package tuic_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/tuic"
)

func TestAdapter_metadata(t *testing.T) {
	a := &tuic.Adapter{}
	if a.Type() != "tuic" {
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
	if len(a.FirewallProtos()) != 1 || a.FirewallProtos()[0] != "udp" {
		t.Fatalf("FirewallProtos() = %#v", a.FirewallProtos())
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
	if !a.NeedsInitialClient(domain.VPNConfig{}) {
		t.Fatal("expected NeedsInitialClient true")
	}
}

func TestRenderInbound_Golden(t *testing.T) {
	data, err := tuic.MarshalProtocolData(tuic.ProtocolData{
		CertPath:   "/etc/obscura/certs/vpn-main.crt",
		KeyPath:    "/etc/obscura/certs/vpn-main.key",
		ServerName: "example.com",
		ALPN:       []string{"h3"},
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &tuic.Adapter{}
	vpn := testVPN(t, data)
	clients := []domain.ClientConfig{testClient("phone", "secret")}
	got, err := adapter.RenderInbound(vpn, clients)
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "../testdata/tuic_inbound.golden.json", got)
}

func TestRenderInbound_BBRGolden(t *testing.T) {
	data, err := tuic.MarshalProtocolData(tuic.ProtocolData{
		CertPath:          "/etc/obscura/certs/vpn-main.crt",
		KeyPath:           "/etc/obscura/certs/vpn-main.key",
		ServerName:        "example.com",
		ALPN:              []string{"h3"},
		CongestionControl: tuic.CongestionBBR,
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &tuic.Adapter{}
	vpn := testVPN(t, data)
	clients := []domain.ClientConfig{testClient("phone", "secret")}
	got, err := adapter.RenderInbound(vpn, clients)
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "../testdata/tuic_inbound_bbr.golden.json", got)
}

func TestRenderInbound_QUICGolden(t *testing.T) {
	data, err := tuic.MarshalProtocolData(tuic.ProtocolData{
		CertPath:          "/etc/obscura/certs/vpn-main.crt",
		KeyPath:           "/etc/obscura/certs/vpn-main.key",
		ServerName:        "example.com",
		ALPN:              []string{"h3"},
		InitialPacketSize: 1200,
		HTTP2:             &tuic.HTTP2Options{IdleTimeout: "30s"},
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &tuic.Adapter{}
	vpn := testVPN(t, data)
	clients := []domain.ClientConfig{testClient("phone", "secret")}
	got, err := adapter.RenderInbound(vpn, clients)
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "../testdata/tuic_inbound_quic.golden.json", got)
}

func TestRenderInbound_extraFields(t *testing.T) {
	data, err := tuic.MarshalProtocolData(tuic.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key",
		AuthTimeout: "10s", ZeroRTTHandshake: true, Heartbeat: "3s",
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &tuic.Adapter{}
	vpn := testVPN(t, data)
	got, err := adapter.RenderInbound(vpn, []domain.ClientConfig{testClient("phone", "secret")})
	if err != nil {
		t.Fatal(err)
	}
	if got["auth_timeout"] != "10s" || got["zero_rtt_handshake"] != true || got["heartbeat"] != "3s" {
		t.Fatalf("fields = %#v", got)
	}
	if got["congestion_control"] != tuic.CongestionCubic {
		t.Fatalf("cc = %#v", got["congestion_control"])
	}
}

func TestRenderInbound_validationError(t *testing.T) {
	adapter := &tuic.Adapter{}
	_, err := adapter.RenderInbound(domain.VPNConfig{}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRenderInbound_parseHookError(t *testing.T) {
	data := validCertData(t)
	restore := tuic.SetParseProtocolDataHookForTest(parseHookFailOnSecond())
	defer restore()
	adapter := &tuic.Adapter{}
	vpn := domain.VPNConfig{
		Name: "main", Tag: "vpn-main",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: data,
	}
	_, err := adapter.RenderInbound(vpn, []domain.ClientConfig{testClient("phone", "secret")})
	if err == nil || !strings.Contains(err.Error(), "parse failed") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestValidateVPN_errors(t *testing.T) {
	adapter := &tuic.Adapter{}
	data := validCertData(t)
	base := domain.VPNConfig{
		Name:         "main",
		Tag:          "vpn-main",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: data,
	}
	clients := []domain.ClientConfig{testClient("phone", "secret")}

	if err := adapter.ValidateVPN(domain.VPNConfig{Tag: "t", Listen: base.Listen, ProtocolData: data}, clients); err == nil {
		t.Fatal("expected name error")
	}
	if err := adapter.ValidateVPN(domain.VPNConfig{Name: "main", Listen: base.Listen, ProtocolData: data}, clients); err == nil {
		t.Fatal("expected tag error")
	}
	badListen := base
	badListen.Listen.ListenPort = 0
	if err := adapter.ValidateVPN(badListen, clients); err == nil {
		t.Fatal("expected listen error")
	}
	badData := base
	badData.ProtocolData = []byte(`{`)
	if err := adapter.ValidateVPN(badData, clients); err == nil {
		t.Fatal("expected parse error")
	}
	if err := adapter.ValidateVPN(base, nil); err == nil {
		t.Fatal("expected client error")
	}
	disabled := []domain.ClientConfig{{Name: "x", Username: testUUID, Password: "p", Enabled: false}}
	if err := adapter.ValidateVPN(base, disabled); err == nil {
		t.Fatal("expected enabled client error")
	}
	badClient := []domain.ClientConfig{{Name: "x", Enabled: true}}
	if err := adapter.ValidateVPN(base, badClient); err == nil {
		t.Fatal("expected validate client error")
	}
	invalidOpts, err := tuic.MarshalProtocolData(tuic.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", CongestionControl: "invalid",
	})
	if err != nil {
		t.Fatal(err)
	}
	invalidVPN := base
	invalidVPN.ProtocolData = invalidOpts
	if err := adapter.ValidateVPN(invalidVPN, clients); err == nil {
		t.Fatal("expected options validation error")
	}
}

func TestValidateClient(t *testing.T) {
	adapter := &tuic.Adapter{}
	if err := adapter.ValidateClient(domain.ClientConfig{}); err == nil {
		t.Fatal("expected uuid error")
	}
	if err := adapter.ValidateClient(domain.ClientConfig{Username: "not-uuid"}); err == nil {
		t.Fatal("expected invalid uuid error")
	}
	if err := adapter.ValidateClient(domain.ClientConfig{Username: testUUID}); err == nil {
		t.Fatal("expected password error")
	}
	if err := adapter.ValidateClient(domain.ClientConfig{Username: testUUID, Password: "p"}); err != nil {
		t.Fatal(err)
	}
}

func TestClientURI(t *testing.T) {
	data, err := tuic.MarshalProtocolData(tuic.ProtocolData{
		CertPath:          "/etc/obscura/certs/vpn-main.crt",
		KeyPath:           "/etc/obscura/certs/vpn-main.key",
		ServerName:        "example.com",
		ALPN:              []string{"h3"},
		CongestionControl: tuic.CongestionBBR,
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &tuic.Adapter{}
	vpn := domain.VPNConfig{
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: data,
	}
	client := domain.ClientConfig{Name: "phone", Username: testUUID, Password: "pass", Enabled: true}
	uri, err := adapter.ClientURI(vpn, []domain.ClientConfig{client}, client, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !containsAll(uri, "tuic://", testUUID+":pass@", "example.com:443", "sni=example.com", "congestion_control=bbr", "alpn=h3", "allow_insecure=1", "#phone") {
		t.Fatalf("unexpected uri: %s", uri)
	}
}

func TestClientURI_defaultCongestion(t *testing.T) {
	data := validCertData(t)
	adapter := &tuic.Adapter{}
	vpn := domain.VPNConfig{
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: data,
	}
	client := domain.ClientConfig{Username: testUUID, Password: "pass", Enabled: true}
	uri, err := adapter.ClientURI(vpn, nil, client, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(uri, "congestion_control=cubic") {
		t.Fatalf("uri = %s", uri)
	}
}

func TestClientURI_errors(t *testing.T) {
	adapter := &tuic.Adapter{}
	vpn := domain.VPNConfig{
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: []byte(`{`),
	}
	client := domain.ClientConfig{Username: testUUID, Password: "pass", Enabled: true}
	if _, err := adapter.ClientURI(vpn, nil, domain.ClientConfig{}, "host"); err == nil {
		t.Fatal("expected validate client error")
	}
	if _, err := adapter.ClientURI(vpn, nil, client, "host"); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestClientQRContent(t *testing.T) {
	data := validCertData(t)
	adapter := &tuic.Adapter{}
	vpn := domain.VPNConfig{
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: data,
	}
	client := domain.ClientConfig{Name: "phone", Username: testUUID, Password: "pass", Enabled: true}
	qr, err := adapter.ClientQRContent(vpn, []domain.ClientConfig{client}, client, "example.com")
	if err != nil || !strings.HasPrefix(qr, "tuic://") {
		t.Fatalf("ClientQRContent() = %q, %v", qr, err)
	}
}

func TestUsersFromClients(t *testing.T) {
	users := tuic.UsersFromClients([]domain.ClientConfig{
		{Name: "enabled", Username: testUUID, Password: "p", Enabled: true},
		{Username: "059032A9-7D40-4A96-9BB1-36823D848069", Password: "p2", Enabled: true},
		{Name: "disabled", Username: testUUID, Password: "p", Enabled: false},
	})
	if len(users) != 2 {
		t.Fatalf("users = %#v", users)
	}
	if users[1]["name"] != "059032A9-7D40-4A96-9BB1-36823D848069" {
		t.Fatalf("fallback name = %#v", users[1])
	}
}

func TestParseProtocolData_adapterPath(t *testing.T) {
	empty, err := tuic.ParseProtocolData(nil)
	if err != nil || empty.ServerName != "" {
		t.Fatalf("empty: %#v, %v", empty, err)
	}
	_, err = tuic.ParseProtocolData([]byte(`{`))
	if err == nil || !strings.Contains(err.Error(), "parse tuic protocol data") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestMarshalProtocolData_roundTrip(t *testing.T) {
	raw, err := tuic.MarshalProtocolData(tuic.ProtocolData{ServerName: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["server_name"] != "example.com" {
		t.Fatalf("decoded = %#v", decoded)
	}
}
