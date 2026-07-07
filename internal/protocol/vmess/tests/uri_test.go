package vmess_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/vmess"
)

func validVPN(t *testing.T, data vmess.ProtocolData) domain.VPNConfig {
	t.Helper()
	raw, err := vmess.MarshalProtocolData(data)
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

func decodeVMessURI(t *testing.T, uri string) map[string]string {
	t.Helper()
	payload, err := base64.StdEncoding.DecodeString(uri[8:])
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]string
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestShareNetType(t *testing.T) {
	cases := map[string]string{
		"ws": "ws", "grpc": "grpc", "http": "http", "httpupgrade": "httpupgrade", "quic": "quic", "": "tcp",
	}
	for transport, want := range cases {
		got := vmess.ShareNetTypeForTest(vmess.ProtocolData{TransportType: transport})
		if got != want {
			t.Fatalf("shareNetType(%q) = %q, want %q", transport, got, want)
		}
	}
}

func TestBuildShareLink_standardTLS(t *testing.T) {
	client := validClient(t)
	vpn := validVPN(t, vmess.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
	})
	uri, err := vmess.BuildShareLinkForTest(vpn, vmess.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
	}, client, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(uri, "vmess://") {
		t.Fatalf("unexpected uri: %q", uri)
	}
	decoded := decodeVMessURI(t, uri)
	if decoded["allowInsecure"] != "1" || decoded["tls"] != "tls" {
		t.Fatalf("unexpected payload: %#v", decoded)
	}
}

func TestBuildShareLink_noTLS(t *testing.T) {
	client := validClient(t)
	vpn := validVPN(t, vmess.ProtocolData{TLSDisabled: true})
	uri, err := vmess.BuildShareLinkForTest(vpn, vmess.ProtocolData{TLSDisabled: true}, client, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	decoded := decodeVMessURI(t, uri)
	if decoded["tls"] != "" {
		t.Fatalf("expected empty tls, got %#v", decoded)
	}
}

func TestBuildShareLink_transports(t *testing.T) {
	client := validClient(t)
	base := vmess.ProtocolData{CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com"}
	vpn := validVPN(t, base)

	t.Run("ws", func(t *testing.T) {
		data := base
		data.TransportType = "ws"
		data.TransportWS = &vmess.TransportWS{Path: "/ws"}
		uri, err := vmess.BuildShareLinkForTest(vpn, data, client, "example.com")
		if err != nil {
			t.Fatal(err)
		}
		decoded := decodeVMessURI(t, uri)
		if decoded["net"] != "ws" || decoded["path"] != "/ws" {
			t.Fatalf("ws payload = %#v", decoded)
		}
	})
	t.Run("http", func(t *testing.T) {
		data := base
		data.TransportType = "http"
		data.TransportHTTP = &vmess.TransportHTTP{Host: []string{"h.example.com"}, Path: "/h"}
		uri, err := vmess.BuildShareLinkForTest(vpn, data, client, "example.com")
		if err != nil {
			t.Fatal(err)
		}
		decoded := decodeVMessURI(t, uri)
		if decoded["host"] != "h.example.com" {
			t.Fatalf("http payload = %#v", decoded)
		}
	})
	t.Run("httpupgrade", func(t *testing.T) {
		data := base
		data.TransportType = "httpupgrade"
		data.TransportHTTPUpgrade = &vmess.TransportHTTPUpgrade{Host: "up.example.com", Path: "/up"}
		uri, err := vmess.BuildShareLinkForTest(vpn, data, client, "example.com")
		if err != nil {
			t.Fatal(err)
		}
		decoded := decodeVMessURI(t, uri)
		if decoded["host"] != "up.example.com" {
			t.Fatalf("httpupgrade payload = %#v", decoded)
		}
	})
	t.Run("grpc", func(t *testing.T) {
		data := base
		data.TransportType = "grpc"
		data.TransportGRPC = &vmess.TransportGRPC{ServiceName: "grpcsvc"}
		uri, err := vmess.BuildShareLinkForTest(vpn, data, client, "example.com")
		if err != nil {
			t.Fatal(err)
		}
		decoded := decodeVMessURI(t, uri)
		if decoded["net"] != "grpc" {
			t.Fatalf("grpc payload = %#v", decoded)
		}
	})
}

func TestBuildShareLink_remarkFromUsername(t *testing.T) {
	client := domain.ClientConfig{Name: "", Username: "5", Password: uuid.NewString(), Enabled: true}
	vpn := validVPN(t, vmess.ProtocolData{CertPath: "/a.crt", KeyPath: "/a.key"})
	uri, err := vmess.BuildShareLinkForTest(vpn, vmess.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key",
	}, client, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	decoded := decodeVMessURI(t, uri)
	if decoded["ps"] != "5" {
		t.Fatalf("expected remark from username, got %#v", decoded)
	}
}

func TestBuildShareLink_acme(t *testing.T) {
	client := validClient(t)
	vpn := validVPN(t, vmess.ProtocolData{
		ACME: &vmess.ACMEOptions{Domains: []string{"example.com"}, Email: "a@b.c"},
	})
	uri, err := vmess.BuildShareLinkForTest(vpn, vmess.ProtocolData{
		ACME: &vmess.ACMEOptions{Domains: []string{"example.com"}, Email: "a@b.c"},
		ALPN: []string{"h2", "http/1.1"},
	}, client, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	decoded := decodeVMessURI(t, uri)
	if decoded["tls"] != "tls" || decoded["alpn"] == "" {
		t.Fatalf("acme payload = %#v", decoded)
	}
}

func TestBuildShareLink_emptySNI(t *testing.T) {
	client := validClient(t)
	vpn := validVPN(t, vmess.ProtocolData{CertPath: "/a.crt", KeyPath: "/a.key"})
	uri, err := vmess.BuildShareLinkForTest(vpn, vmess.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key",
	}, client, "proxy.example.com")
	if err != nil {
		t.Fatal(err)
	}
	decoded := decodeVMessURI(t, uri)
	if decoded["sni"] != "proxy.example.com" {
		t.Fatalf("expected sni from host, got %#v", decoded)
	}
}

func TestBuildShareLink_realityTLS(t *testing.T) {
	client := validClient(t)
	vpn := validVPN(t, vmess.ProtocolData{
		RealityEnabled: true, RealityPrivateKey: "k", RealityShortIDs: []string{"ab"},
		RealityHandshakeServer: "www.bing.com", RealityUTLSFingerprint: "chrome",
	})
	uri, err := vmess.BuildShareLinkForTest(vpn, vmess.ProtocolData{
		RealityEnabled: true, RealityPrivateKey: "k", RealityShortIDs: []string{"ab"},
		RealityHandshakeServer: "www.bing.com", RealityUTLSFingerprint: "chrome",
		ServerName: "example.com",
	}, client, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	decoded := decodeVMessURI(t, uri)
	if decoded["allowInsecure"] != "" {
		t.Fatalf("reality should not set allowInsecure, got %#v", decoded)
	}
}

func TestBuildShareLink_jsonMarshalError(t *testing.T) {
	restore := vmess.SetJSONMarshalHookForTest(func(any) ([]byte, error) {
		return nil, errors.New("marshal failed")
	})
	defer restore()
	client := validClient(t)
	vpn := validVPN(t, vmess.ProtocolData{CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com"})
	_, err := vmess.BuildShareLinkForTest(vpn, vmess.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
	}, client, "example.com")
	if err == nil || !strings.Contains(err.Error(), "marshal failed") {
		t.Fatalf("expected marshal error, got %v", err)
	}
}

func TestBuildShareLink_alterIDError(t *testing.T) {
	client := domain.ClientConfig{Name: "phone", Password: uuid.NewString(), Username: "bad", Enabled: true}
	vpn := validVPN(t, vmess.ProtocolData{CertPath: "/a.crt", KeyPath: "/a.key"})
	_, err := vmess.BuildShareLinkForTest(vpn, vmess.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key",
	}, client, "example.com")
	if err == nil || !strings.Contains(err.Error(), "client alterId") {
		t.Fatalf("expected alterId error, got %v", err)
	}
}
