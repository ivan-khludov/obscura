package hysteria2_test

import (
	"encoding/json"
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol/hysteria2"
)

func TestRenderTLS(t *testing.T) {
	tls := hysteria2.RenderTLSForTest(hysteria2.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com", ALPN: []string{"h3"},
	})
	if tls["server_name"] != "example.com" {
		t.Fatalf("tls = %#v", tls)
	}
}

func TestRenderObfs(t *testing.T) {
	if hysteria2.RenderObfsForTest(hysteria2.ProtocolData{}) != nil {
		t.Fatal("expected nil obfs")
	}
	obfs := hysteria2.RenderObfsForTest(hysteria2.ProtocolData{ObfsPassword: "secret"})
	if obfs["type"] != "salamander" || obfs["password"] != "secret" {
		t.Fatalf("obfs = %#v", obfs)
	}
}

func TestRenderMasquerade(t *testing.T) {
	if hysteria2.RenderMasqueradeForTest(hysteria2.ProtocolData{}) != nil {
		t.Fatal("expected nil")
	}
	if got := hysteria2.RenderMasqueradeForTest(hysteria2.ProtocolData{MasqueradeURL: "http://x"}); got != "http://x" {
		t.Fatalf("url masq = %#v", got)
	}
	file := hysteria2.RenderMasqueradeForTest(hysteria2.ProtocolData{
		Masquerade: &hysteria2.MasqueradeObject{Type: hysteria2.MasqueradeTypeFile, Directory: "/www"},
	}).(map[string]any)
	if file["directory"] != "/www" {
		t.Fatalf("file = %#v", file)
	}
	proxy := hysteria2.RenderMasqueradeForTest(hysteria2.ProtocolData{
		Masquerade: &hysteria2.MasqueradeObject{Type: hysteria2.MasqueradeTypeProxy, URL: "http://p", RewriteHost: true},
	}).(map[string]any)
	if proxy["rewrite_host"] != true {
		t.Fatalf("proxy = %#v", proxy)
	}
	stringMasq := hysteria2.RenderMasqueradeForTest(hysteria2.ProtocolData{
		Masquerade: &hysteria2.MasqueradeObject{
			Type: hysteria2.MasqueradeTypeString, StatusCode: 200,
			Headers: map[string]string{"X": "1"}, Content: "ok",
		},
	}).(map[string]any)
	if stringMasq["headers"] == nil || stringMasq["content"] != "ok" {
		t.Fatalf("string masq = %#v", stringMasq)
	}
	stringNoExtras := hysteria2.RenderMasqueradeForTest(hysteria2.ProtocolData{
		Masquerade: &hysteria2.MasqueradeObject{Type: hysteria2.MasqueradeTypeString, StatusCode: 204},
	}).(map[string]any)
	if _, ok := stringNoExtras["headers"]; ok {
		t.Fatalf("expected no headers: %#v", stringNoExtras)
	}
}

func TestRenderRealm(t *testing.T) {
	if hysteria2.RenderRealmForTest(nil) != nil {
		t.Fatal("expected nil")
	}
	realm := hysteria2.RenderRealmForTest(&hysteria2.RealmOptions{
		ServerURL: "https://realm", RealmID: "id", STUNServers: []string{"stun:1"}, Token: "tok",
		STUNDomainResolver: json.RawMessage(`"local"`),
		HTTPClient:         json.RawMessage(`{"timeout":"5s"}`),
	})
	if realm["token"] != "tok" || realm["stun_domain_resolver"] == nil || realm["http_client"] == nil {
		t.Fatalf("realm = %#v", realm)
	}
	badJSON := hysteria2.RenderRealmForTest(&hysteria2.RealmOptions{
		ServerURL: "https://realm", RealmID: "id", STUNServers: []string{"stun:1"},
		STUNDomainResolver: json.RawMessage(`{`),
		HTTPClient:         json.RawMessage(`{`),
	})
	if _, ok := badJSON["stun_domain_resolver"]; ok {
		t.Fatalf("expected invalid resolver omitted: %#v", badJSON)
	}
	if _, ok := badJSON["http_client"]; ok {
		t.Fatalf("expected invalid client omitted: %#v", badJSON)
	}
}

func TestApplyQUICFields(t *testing.T) {
	target := map[string]any{}
	hysteria2.ApplyQUICFieldsForTest(target, hysteria2.ProtocolData{
		InitialPacketSize: 1200, DisablePathMTUDiscovery: true,
		HTTP2: &hysteria2.HTTP2Options{IdleTimeout: "30s"},
	})
	if target["initial_packet_size"] != 1200 || target["disable_path_mtu_discovery"] != true {
		t.Fatalf("quic = %#v", target)
	}
}
