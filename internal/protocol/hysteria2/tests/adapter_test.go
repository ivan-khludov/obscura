package hysteria2_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/hysteria2"
)

func TestAdapter_metadata(t *testing.T) {
	a := &hysteria2.Adapter{}
	if a.Type() != "hysteria2" {
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
	data, err := hysteria2.MarshalProtocolData(hysteria2.ProtocolData{
		CertPath:   "/etc/obscura/certs/vpn-main.crt",
		KeyPath:    "/etc/obscura/certs/vpn-main.key",
		ServerName: "example.com",
		ALPN:       []string{"h3"},
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &hysteria2.Adapter{}
	vpn := testVPN(t, data)
	clients := []domain.ClientConfig{testClient("phone", "secret")}
	got, err := adapter.RenderInbound(vpn, clients)
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "../testdata/hysteria2_inbound.golden.json", got)
}

func TestRenderInbound_ObfsGolden(t *testing.T) {
	data, err := hysteria2.MarshalProtocolData(hysteria2.ProtocolData{
		CertPath:     "/etc/obscura/certs/vpn-main.crt",
		KeyPath:      "/etc/obscura/certs/vpn-main.key",
		ServerName:   "example.com",
		ALPN:         []string{"h3"},
		ObfsPassword: "obfs-secret",
		UpMbps:       100,
		DownMbps:     100,
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &hysteria2.Adapter{}
	vpn := testVPN(t, data)
	clients := []domain.ClientConfig{testClient("phone", "secret")}
	got, err := adapter.RenderInbound(vpn, clients)
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "../testdata/hysteria2_inbound_obfs.golden.json", got)
}

func TestRenderInbound_MasqueradeProxyGolden(t *testing.T) {
	data, err := hysteria2.MarshalProtocolData(hysteria2.ProtocolData{
		CertPath:   "/etc/obscura/certs/vpn-main.crt",
		KeyPath:    "/etc/obscura/certs/vpn-main.key",
		ServerName: "example.com",
		ALPN:       []string{"h3"},
		Masquerade: &hysteria2.MasqueradeObject{
			Type:        hysteria2.MasqueradeTypeProxy,
			URL:         "http://127.0.0.1:8080",
			RewriteHost: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &hysteria2.Adapter{}
	vpn := testVPN(t, data)
	clients := []domain.ClientConfig{testClient("phone", "secret")}
	got, err := adapter.RenderInbound(vpn, clients)
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "../testdata/hysteria2_inbound_masquerade_proxy.golden.json", got)
}

func TestRenderInbound_RealmGolden(t *testing.T) {
	data, err := hysteria2.MarshalProtocolData(hysteria2.ProtocolData{
		CertPath:          "/etc/obscura/certs/vpn-main.crt",
		KeyPath:           "/etc/obscura/certs/vpn-main.key",
		ServerName:        "example.com",
		ALPN:              []string{"h3"},
		BBRProfile:        hysteria2.BBRProfileStandard,
		InitialPacketSize: 1200,
		Realm: &hysteria2.RealmOptions{
			ServerURL:   "https://realm.example.com",
			Token:       "token",
			RealmID:     "my-realm",
			STUNServers: []string{"stun.l.google.com:19302"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &hysteria2.Adapter{}
	vpn := testVPN(t, data)
	clients := []domain.ClientConfig{testClient("phone", "secret")}
	got, err := adapter.RenderInbound(vpn, clients)
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "../testdata/hysteria2_inbound_realm.golden.json", got)
}

func TestRenderInbound_extraFields(t *testing.T) {
	data, err := hysteria2.MarshalProtocolData(hysteria2.ProtocolData{
		CertPath:              "/etc/obscura/certs/vpn-main.crt",
		KeyPath:               "/etc/obscura/certs/vpn-main.key",
		ServerName:            "example.com",
		IgnoreClientBandwidth: true,
		BrutalDebug:           true,
		MasqueradeURL:         "http://fallback.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &hysteria2.Adapter{}
	vpn := testVPN(t, data)
	clients := []domain.ClientConfig{testClient("phone", "secret")}
	got, err := adapter.RenderInbound(vpn, clients)
	if err != nil {
		t.Fatal(err)
	}
	if got["ignore_client_bandwidth"] != true || got["brutal_debug"] != true {
		t.Fatalf("unexpected flags: %#v", got)
	}
	if got["masquerade"] != "http://fallback.example.com" {
		t.Fatalf("masquerade = %#v", got["masquerade"])
	}
}

func TestRenderInbound_validationError(t *testing.T) {
	adapter := &hysteria2.Adapter{}
	_, err := adapter.RenderInbound(domain.VPNConfig{}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRenderInbound_parseHookError(t *testing.T) {
	data := validCertData(t)
	restore := hysteria2.SetParseProtocolDataHookForTest(parseHookFailOnSecond())
	defer restore()
	adapter := &hysteria2.Adapter{}
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
	adapter := &hysteria2.Adapter{}
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
	disabled := []domain.ClientConfig{{Name: "x", Password: "p", Enabled: false}}
	if err := adapter.ValidateVPN(base, disabled); err == nil {
		t.Fatal("expected enabled client error")
	}
	badClient := []domain.ClientConfig{{Name: "x", Enabled: true}}
	if err := adapter.ValidateVPN(base, badClient); err == nil {
		t.Fatal("expected validate client error")
	}
	invalidOpts, err := hysteria2.MarshalProtocolData(hysteria2.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", BBRProfile: "invalid",
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
	adapter := &hysteria2.Adapter{}
	if err := adapter.ValidateClient(domain.ClientConfig{}); err == nil {
		t.Fatal("expected password error")
	}
	if err := adapter.ValidateClient(domain.ClientConfig{Password: "p"}); err != nil {
		t.Fatal(err)
	}
}

func TestClientURI(t *testing.T) {
	data, err := hysteria2.MarshalProtocolData(hysteria2.ProtocolData{
		CertPath:     "/etc/obscura/certs/vpn-main.crt",
		KeyPath:      "/etc/obscura/certs/vpn-main.key",
		ServerName:   "example.com",
		ALPN:         []string{"h3"},
		ObfsPassword: "obfs-secret",
		UpMbps:       50,
		DownMbps:     75,
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &hysteria2.Adapter{}
	vpn := domain.VPNConfig{
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: data,
	}
	client := domain.ClientConfig{Name: "phone", Password: "pass", Enabled: true}
	uri, err := adapter.ClientURI(vpn, []domain.ClientConfig{client}, client, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !containsAll(uri, "hysteria2://", "phone:pass@", "example.com:443", "sni=example.com", "obfs=salamander", "obfs-password=obfs-secret", "insecure=1", "upmbps=50", "downmbps=75", "#phone") {
		t.Fatalf("unexpected uri: %s", uri)
	}
}

func TestClientURI_noName(t *testing.T) {
	data := validCertData(t)
	adapter := &hysteria2.Adapter{}
	vpn := domain.VPNConfig{
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: data,
	}
	client := domain.ClientConfig{Username: "user", Password: "pass", Enabled: true}
	uri, err := adapter.ClientURI(vpn, nil, client, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !containsAll(uri, "hysteria2://pass@", "#user") {
		t.Fatalf("unexpected uri: %s", uri)
	}
}

func TestClientURI_PerVPNClientHost(t *testing.T) {
	data := validCertData(t)
	adapter := &hysteria2.Adapter{}
	vpn := domain.VPNConfig{
		ClientHost:   "culhackervpn.duckdns.org",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 20783},
		ProtocolData: data,
	}
	client := domain.ClientConfig{Name: "phone", Password: "pass", Enabled: true}
	uri, err := adapter.ClientURI(vpn, []domain.ClientConfig{client}, client, "hostname.local")
	if err != nil {
		t.Fatal(err)
	}
	if !containsAll(uri, "culhackervpn.duckdns.org:20783") {
		t.Fatalf("unexpected uri: %s", uri)
	}
}

func TestClientURI_errors(t *testing.T) {
	adapter := &hysteria2.Adapter{}
	vpn := domain.VPNConfig{
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: []byte(`{`),
	}
	client := domain.ClientConfig{Name: "phone", Password: "pass", Enabled: true}
	if _, err := adapter.ClientURI(vpn, nil, domain.ClientConfig{}, "host"); err == nil {
		t.Fatal("expected password error")
	}
	if _, err := adapter.ClientURI(vpn, nil, client, "host"); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestClientQRContent(t *testing.T) {
	data := validCertData(t)
	adapter := &hysteria2.Adapter{}
	vpn := domain.VPNConfig{
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: data,
	}
	client := domain.ClientConfig{Name: "phone", Password: "pass", Enabled: true}
	qr, err := adapter.ClientQRContent(vpn, []domain.ClientConfig{client}, client, "example.com")
	if err != nil || !strings.HasPrefix(qr, "hysteria2://") {
		t.Fatalf("ClientQRContent() = %q, %v", qr, err)
	}
}

func TestBuildClientURI_bandwidthOnly(t *testing.T) {
	data, err := hysteria2.MarshalProtocolData(hysteria2.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", UpMbps: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	vpn := domain.VPNConfig{Listen: domain.ListenOptions{ListenPort: 443}, ProtocolData: data}
	uri, err := hysteria2.BuildClientURI(vpn, domain.ClientConfig{Password: "p"}, "host")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(uri, "upmbps=10") {
		t.Fatalf("uri = %s", uri)
	}
}

func TestUsersFromClients(t *testing.T) {
	users := hysteria2.UsersFromClients([]domain.ClientConfig{
		{Name: "enabled", Password: "p", Enabled: true},
		{Username: "u", Password: "p2", Enabled: true},
		{Name: "disabled", Password: "p", Enabled: false},
	})
	if len(users) != 2 {
		t.Fatalf("users = %#v", users)
	}
	if users[1]["name"] != "u" {
		t.Fatalf("fallback name = %#v", users[1])
	}
}

func TestParseProtocolData_adapterPath(t *testing.T) {
	empty, err := hysteria2.ParseProtocolData(nil)
	if err != nil || empty.ServerName != "" {
		t.Fatalf("empty: %#v, %v", empty, err)
	}
	_, err = hysteria2.ParseProtocolData([]byte(`{`))
	if err == nil || !strings.Contains(err.Error(), "parse hysteria2 protocol data") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestMarshalProtocolData_roundTrip(t *testing.T) {
	raw, err := hysteria2.MarshalProtocolData(hysteria2.ProtocolData{ServerName: "example.com"})
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
