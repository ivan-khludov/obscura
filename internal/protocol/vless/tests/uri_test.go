package vless_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/vless"
)

func validVPN(t *testing.T, data vless.ProtocolData) domain.VPNConfig {
	t.Helper()
	raw, err := vless.MarshalProtocolData(data)
	if err != nil {
		t.Fatal(err)
	}
	return domain.VPNConfig{
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: raw,
	}
}

func validClient(t *testing.T) domain.ClientConfig {
	t.Helper()
	return domain.ClientConfig{Name: "phone", Password: uuid.NewString(), Enabled: true}
}

func TestShareNetType(t *testing.T) {
	cases := map[string]string{
		"ws": "ws", "grpc": "grpc", "http": "http", "httpupgrade": "httpupgrade", "quic": "quic", "": "tcp",
	}
	for transport, want := range cases {
		got := vless.ShareNetTypeForTest(vless.ProtocolData{TransportType: transport})
		if got != want {
			t.Fatalf("shareNetType(%q) = %q, want %q", transport, got, want)
		}
	}
}

func TestBuildShareLink_standardTLS(t *testing.T) {
	client := validClient(t)
	vpn := validVPN(t, vless.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
	})
	uri, err := vless.BuildShareLinkForTest(vpn, vless.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
	}, client, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(uri, "vless://") {
		t.Fatalf("unexpected uri: %q", uri)
	}
	if !strings.Contains(uri, "allowInsecure=1") {
		t.Fatalf("expected allowInsecure, got %q", uri)
	}
	if !strings.Contains(uri, "security=tls") {
		t.Fatalf("expected tls security, got %q", uri)
	}
}

func TestBuildShareLink_reality(t *testing.T) {
	client := validClient(t)
	vpn := validVPN(t, vless.ProtocolData{RealityEnabled: true, ServerName: "example.com"})
	uri, err := vless.BuildShareLinkForTest(vpn, vless.ProtocolData{
		RealityEnabled: true, RealityPublicKey: "pub", RealityShortIDs: []string{"abcd"},
		ServerName: "example.com",
	}, client, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(uri, "allowInsecure") {
		t.Fatalf("reality uri must not include allowInsecure, got %q", uri)
	}
	if !strings.Contains(uri, "fp=chrome") {
		t.Fatalf("expected fp=chrome, got %q", uri)
	}
	if !strings.Contains(uri, "pbk=pub") {
		t.Fatalf("expected pbk, got %q", uri)
	}
}

func TestBuildShareLink_realityFingerprint(t *testing.T) {
	client := validClient(t)
	vpn := validVPN(t, vless.ProtocolData{RealityEnabled: true})
	uri, err := vless.BuildShareLinkForTest(vpn, vless.ProtocolData{
		RealityEnabled: true, RealityPublicKey: "pub", RealityShortIDs: []string{"abcd"},
		RealityUTLSFingerprint: "firefox", ServerName: "example.com",
	}, client, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(uri, "fp=firefox") {
		t.Fatalf("expected fp=firefox, got %q", uri)
	}
}

func TestBuildShareLink_transports(t *testing.T) {
	client := validClient(t)
	base := vless.ProtocolData{CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com"}
	vpn := validVPN(t, base)

	t.Run("ws", func(t *testing.T) {
		data := base
		data.TransportType = "ws"
		data.TransportWS = &vless.TransportWS{Path: "/ws"}
		uri, err := vless.BuildShareLinkForTest(vpn, data, client, "example.com")
		if err != nil || !strings.Contains(uri, "type=ws") || !strings.Contains(uri, "path=%2Fws") {
			t.Fatalf("ws uri = %q, %v", uri, err)
		}
	})
	t.Run("http", func(t *testing.T) {
		data := base
		data.TransportType = "http"
		data.TransportHTTP = &vless.TransportHTTP{Host: []string{"h.example.com"}, Path: "/h"}
		uri, err := vless.BuildShareLinkForTest(vpn, data, client, "example.com")
		if err != nil || !strings.Contains(uri, "host=h.example.com") {
			t.Fatalf("http uri = %q, %v", uri, err)
		}
	})
	t.Run("httpupgrade", func(t *testing.T) {
		data := base
		data.TransportType = "httpupgrade"
		data.TransportHTTPUpgrade = &vless.TransportHTTPUpgrade{Host: "up.example.com", Path: "/up"}
		uri, err := vless.BuildShareLinkForTest(vpn, data, client, "example.com")
		if err != nil || !strings.Contains(uri, "host=up.example.com") {
			t.Fatalf("httpupgrade uri = %q, %v", uri, err)
		}
	})
	t.Run("grpc", func(t *testing.T) {
		data := base
		data.TransportType = "grpc"
		data.TransportGRPC = &vless.TransportGRPC{ServiceName: "grpcsvc"}
		uri, err := vless.BuildShareLinkForTest(vpn, data, client, "example.com")
		if err != nil || !strings.Contains(uri, "path=grpcsvc") {
			t.Fatalf("grpc uri = %q, %v", uri, err)
		}
	})
}

func TestBuildShareLink_flowAndRemark(t *testing.T) {
	client := domain.ClientConfig{Password: uuid.NewString(), Enabled: true}
	vpn := validVPN(t, vless.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", DefaultFlow: vless.FlowVision,
	})
	uri, err := vless.BuildShareLinkForTest(vpn, vless.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", DefaultFlow: vless.FlowVision,
	}, client, "example.com")
	if err != nil || !strings.Contains(uri, "flow=xtls-rprx-vision") {
		t.Fatalf("flow uri = %q, %v", uri, err)
	}
	if !strings.Contains(uri, "#vless") {
		t.Fatalf("expected default remark vless, got %q", uri)
	}
}

func TestBuildShareLink_acme(t *testing.T) {
	client := validClient(t)
	vpn := validVPN(t, vless.ProtocolData{
		ACME: &vless.ACMEOptions{Domains: []string{"example.com"}, Email: "a@b.c"},
	})
	uri, err := vless.BuildShareLinkForTest(vpn, vless.ProtocolData{
		ACME: &vless.ACMEOptions{Domains: []string{"example.com"}, Email: "a@b.c"},
		ALPN: []string{"h2", "http/1.1"},
	}, client, "example.com")
	if err != nil || !strings.Contains(uri, "security=tls") {
		t.Fatalf("acme uri = %q, %v", uri, err)
	}
}

func TestBuildShareLink_httpUpgradeOnly(t *testing.T) {
	client := validClient(t)
	vpn := validVPN(t, vless.ProtocolData{CertPath: "/a.crt", KeyPath: "/a.key"})
	uri, err := vless.BuildShareLinkForTest(vpn, vless.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key",
		TransportType:        "httpupgrade",
		TransportHTTPUpgrade: &vless.TransportHTTPUpgrade{Host: "up.example.com", Path: "/up"},
	}, client, "example.com")
	if err != nil || !strings.Contains(uri, "host=up.example.com") {
		t.Fatalf("httpupgrade uri = %q, %v", uri, err)
	}
}

func TestBuildShareLink_quic(t *testing.T) {
	if vless.ShareNetTypeForTest(vless.ProtocolData{TransportType: "quic"}) != "quic" {
		t.Fatal("expected quic net type")
	}
}

func TestBuildShareLink_flowError(t *testing.T) {
	client := validClient(t)
	vpn := validVPN(t, vless.ProtocolData{CertPath: "/a.crt", KeyPath: "/a.key"})
	_, err := vless.BuildShareLinkForTest(vpn, vless.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", DefaultFlow: vless.FlowVision,
		TransportType: "ws", TransportWS: &vless.TransportWS{Path: "/"},
	}, client, "example.com")
	if err == nil || !strings.Contains(err.Error(), "client flow") {
		t.Fatalf("expected client flow error, got %v", err)
	}
}
