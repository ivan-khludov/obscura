package trojan_test

import (
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/trojan"
)

func TestRenderTLS_standard(t *testing.T) {
	tls := trojan.RenderTLSForTest(trojan.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
		ALPN:       []string{"h2", "http/1.1"},
		MinVersion: "1.2", MaxVersion: "1.3",
		CipherSuites:                     []string{"TLS_AES_128_GCM_SHA256"},
		CurvePreferences:                 []string{"X25519"},
		ClientAuthentication:             "require",
		ClientCertificatePaths:           []string{"/client.crt"},
		ClientCertificatePublicKeySHA256: []string{"abc"},
		KernelTX:                         true, KernelRX: true, HandshakeTimeout: "5s",
	})
	if tls["enabled"] != true || tls["server_name"] != "example.com" {
		t.Fatalf("unexpected tls: %#v", tls)
	}
}

func TestRenderTLS_realityCustomPort(t *testing.T) {
	tls := trojan.RenderTLSForTest(trojan.ProtocolData{
		RealityEnabled: true, RealityPrivateKey: "k", RealityShortIDs: []string{"ab"},
		RealityHandshakeServer: "www.bing.com", RealityHandshakePort: 8443,
		RealityMaxTimeDifference: "1m",
	})
	reality, ok := tls["reality"].(map[string]any)
	if !ok {
		t.Fatalf("expected reality block: %#v", tls)
	}
	handshake, ok := reality["handshake"].(map[string]any)
	if !ok || handshake["server_port"] != 8443 {
		t.Fatalf("handshake port = %#v", reality["handshake"])
	}
}

func TestRenderTLS_realityDefaultPort(t *testing.T) {
	data := trojan.ProtocolData{
		RealityEnabled: true, RealityPrivateKey: "k", RealityShortIDs: []string{"ab"},
		RealityHandshakeServer: "www.bing.com",
	}
	if got := trojan.RealityHandshakePortForTest(data); got != trojan.DefaultRealityHandshakePort {
		t.Fatalf("default port = %d want %d", got, trojan.DefaultRealityHandshakePort)
	}
	tls := trojan.RenderTLSForTest(data)
	reality := tls["reality"].(map[string]any)
	handshake := reality["handshake"].(map[string]any)
	if handshake["server_port"] != trojan.DefaultRealityHandshakePort {
		t.Fatalf("rendered port = %#v", handshake["server_port"])
	}
}

func TestRenderTLS_acmeAndECH(t *testing.T) {
	tls := trojan.RenderTLSForTest(trojan.ProtocolData{
		ACME:       &trojan.ACMEOptions{Domains: []string{"example.com"}, Email: "a@b.c"},
		ECHEnabled: true, ECHKeyPath: "/ech.key",
	})
	if tls["acme"] == nil || tls["ech"] == nil {
		t.Fatalf("expected acme and ech: %#v", tls)
	}
}

func TestRenderMultiplex(t *testing.T) {
	mux := trojan.RenderMultiplexForTest(trojan.ProtocolData{MultiplexPadding: true})
	if mux["enabled"] != true || mux["padding"] != true {
		t.Fatalf("unexpected multiplex: %#v", mux)
	}
}

func TestRenderFallback(t *testing.T) {
	fb, fbALPN := trojan.RenderFallbackForTest(trojan.ProtocolData{
		FallbackServer: "127.0.0.1", FallbackPort: 8080,
		FallbackForALPN: map[string]trojan.FallbackTarget{
			"h2": {Server: "127.0.0.1", ServerPort: 9090},
		},
	})
	if fb == nil || fbALPN == nil {
		t.Fatalf("expected fallback maps: %#v %#v", fb, fbALPN)
	}
}

func TestRenderFallback_empty(t *testing.T) {
	fb, fbALPN := trojan.RenderFallbackForTest(trojan.ProtocolData{})
	if fb != nil || fbALPN != nil {
		t.Fatalf("expected nil fallback: %#v %#v", fb, fbALPN)
	}
}

func TestRenderTransport_allTypes(t *testing.T) {
	cases := []struct {
		name string
		data trojan.ProtocolData
	}{
		{"quic", trojan.ProtocolData{TransportType: "quic"}},
		{"http", trojan.ProtocolData{TransportType: "http", TransportHTTP: &trojan.TransportHTTP{Path: "/p", Host: []string{"h"}}}},
		{"ws", trojan.ProtocolData{TransportType: "ws", TransportWS: &trojan.TransportWS{Path: "/w"}}},
		{"grpc", trojan.ProtocolData{TransportType: "grpc", TransportGRPC: &trojan.TransportGRPC{ServiceName: "svc"}}},
		{"httpupgrade", trojan.ProtocolData{TransportType: "httpupgrade", TransportHTTPUpgrade: &trojan.TransportHTTPUpgrade{Path: "/u"}}},
		{"tcp", trojan.ProtocolData{TransportType: ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := trojan.RenderTransportForTest(tc.data)
			if tc.name == "tcp" && got != nil {
				t.Fatalf("expected nil transport for tcp, got %#v", got)
			}
			if tc.name != "tcp" && got == nil {
				t.Fatal("expected transport fragment")
			}
		})
	}
}

func TestUsersFromClients_viaRender(t *testing.T) {
	data, err := trojan.MarshalProtocolData(trojan.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := (&trojan.Adapter{}).RenderInbound(
		testVPN(t, data),
		[]domain.ClientConfig{
			{Username: "u", Password: "p", Enabled: true},
			{Name: "disabled", Password: "p", Enabled: false},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	users, ok := got["users"].([]map[string]string)
	if !ok {
		usersAny, ok2 := got["users"].([]any)
		if !ok2 || len(usersAny) != 1 {
			t.Fatalf("users = %#v", got["users"])
		}
		return
	}
	if len(users) != 1 || users[0]["name"] != "u" {
		t.Fatalf("unexpected users: %#v", got["users"])
	}
}
