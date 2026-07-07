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

func TestAdapter_metadata(t *testing.T) {
	a := &vmess.Adapter{}
	if a.Type() != "vmess" {
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
	data, err := vmess.MarshalProtocolData(vmess.ProtocolData{
		CertPath:   "/etc/obscura/certs/vpn-main.crt",
		KeyPath:    "/etc/obscura/certs/vpn-main.key",
		ServerName: "example.com",
		ALPN:       []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &vmess.Adapter{}
	vpn := domain.VPNConfig{
		Name: "main", Protocol: "vmess", Tag: "vpn-main", Enabled: true,
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
	assertGolden(t, "../testdata/vmess_inbound.golden.json", got)
}

func TestRenderInbound_NoTLS(t *testing.T) {
	clientUUID := uuid.NewString()
	data, err := vmess.MarshalProtocolData(vmess.ProtocolData{TLSDisabled: true})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &vmess.Adapter{}
	vpn := domain.VPNConfig{
		Name: "main", Protocol: "vmess", Tag: "vpn-main", Enabled: true,
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 16823},
		ProtocolData: data,
	}
	got, err := adapter.RenderInbound(vpn, []domain.ClientConfig{
		{Name: "phone", Password: clientUUID, Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["tls"]; ok {
		t.Fatal("expected no tls block")
	}
}

func TestRenderInbound_multiplexAndTransport(t *testing.T) {
	data, err := vmess.MarshalProtocolData(vmess.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
		Multiplex:     true,
		TransportType: "grpc", TransportGRPC: &vmess.TransportGRPC{ServiceName: "svc"},
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &vmess.Adapter{}
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

func TestRenderInbound_usersFromClientsError(t *testing.T) {
	clientUUID := uuid.NewString()
	data, err := vmess.MarshalProtocolData(vmess.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	vpn := domain.VPNConfig{
		Name: "main", Tag: "vpn-main",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: data,
	}
	calls := 0
	restore := vmess.SetUsersFromClientsHookForTest(func(_ vmess.ProtocolData, _ []domain.ClientConfig) ([]map[string]any, error) {
		calls++
		if calls >= 2 {
			return nil, errors.New("users failed")
		}
		return []map[string]any{{"name": "phone", "uuid": clientUUID, "alterId": 0}}, nil
	})
	defer restore()
	_, err = (&vmess.Adapter{}).RenderInbound(vpn, []domain.ClientConfig{
		{Name: "phone", Password: clientUUID, Enabled: true},
	})
	if err == nil || !strings.Contains(err.Error(), "users failed") {
		t.Fatalf("expected users error, got %v", err)
	}
}

func TestRenderInbound_parseError(t *testing.T) {
	clientUUID := uuid.NewString()
	data, err := vmess.MarshalProtocolData(vmess.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	vpn := domain.VPNConfig{
		Name: "main", Tag: "vpn-main",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: data,
	}
	restore := vmess.SetParseProtocolDataHookForTest(parseHookFailOnSecond())
	defer restore()
	_, err = (&vmess.Adapter{}).RenderInbound(vpn, []domain.ClientConfig{
		{Name: "phone", Password: clientUUID, Enabled: true},
	})
	if err == nil || err.Error() != "parse failed" {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestRenderInbound_errors(t *testing.T) {
	adapter := &vmess.Adapter{}
	_, err := adapter.RenderInbound(domain.VPNConfig{}, nil)
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateVPN(t *testing.T) {
	validData, _ := vmess.MarshalProtocolData(vmess.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
	})
	validVPN := domain.VPNConfig{
		Name: "main", Tag: "vpn-main",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: validData,
	}
	validClient := domain.ClientConfig{Name: "phone", Password: uuid.NewString(), Enabled: true}
	adapter := &vmess.Adapter{}

	if err := adapter.ValidateVPN(validVPN, []domain.ClientConfig{validClient}); err != nil {
		t.Fatalf("valid vpn: %v", err)
	}
	noTLSData, _ := vmess.MarshalProtocolData(vmess.ProtocolData{TLSDisabled: true})
	noTLSVPN := domain.VPNConfig{
		Name: "main", Tag: "vpn-main",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 16823},
		ProtocolData: noTLSData,
	}
	if err := adapter.ValidateVPN(noTLSVPN, []domain.ClientConfig{validClient}); err != nil {
		t.Fatalf("no tls vpn: %v", err)
	}
	if err := adapter.ValidateVPN(domain.VPNConfig{Tag: "t", ProtocolData: validData}, nil); err == nil {
		t.Fatal("expected name required")
	}
	if err := adapter.ValidateVPN(domain.VPNConfig{Name: "n", ProtocolData: validData}, nil); err == nil {
		t.Fatal("expected tag required")
	}
	if err := adapter.ValidateVPN(validVPN, []domain.ClientConfig{
		validClient,
		{Name: "off", Password: uuid.NewString(), Enabled: false},
	}); err != nil {
		t.Fatalf("valid vpn with disabled client: %v", err)
	}
	if err := adapter.ValidateVPN(validVPN, nil); err == nil {
		t.Fatal("expected enabled client error")
	}
	badClient := domain.ClientConfig{Name: "bad", Password: "not-uuid", Enabled: true}
	if err := adapter.ValidateVPN(validVPN, []domain.ClientConfig{badClient}); err == nil {
		t.Fatal("expected client validation error")
	}
	badAlterData, _ := vmess.MarshalProtocolData(vmess.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
	})
	badAlterVPN := domain.VPNConfig{
		Name: "main", Tag: "vpn-main",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: badAlterData,
	}
	restoreUsers := vmess.SetUsersFromClientsHookForTest(func(vmess.ProtocolData, []domain.ClientConfig) ([]map[string]any, error) {
		return nil, errors.New("users failed")
	})
	defer restoreUsers()
	if err := adapter.ValidateVPN(badAlterVPN, []domain.ClientConfig{validClient}); err == nil || !strings.Contains(err.Error(), "users failed") {
		t.Fatalf("expected users error, got %v", err)
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
}

func TestRenderInbound_usersError(t *testing.T) {
	data, _ := vmess.MarshalProtocolData(vmess.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", TransportType: "ws",
	})
	adapter := &vmess.Adapter{}
	vpn := domain.VPNConfig{
		Name: "main", Tag: "vpn-main",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: data,
	}
	_, err := adapter.RenderInbound(vpn, []domain.ClientConfig{
		{Name: "phone", Password: uuid.NewString(), Enabled: true},
	})
	if err == nil {
		t.Fatal("expected transport validation error")
	}
}

func TestValidateClient(t *testing.T) {
	adapter := &vmess.Adapter{}
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
		Password: uuid.NewString(), Username: "2",
	}); err != nil {
		t.Fatal(err)
	}
	if err := adapter.ValidateClient(domain.ClientConfig{
		Password: uuid.NewString(), Username: "bad",
	}); err == nil {
		t.Fatal("expected alterId validation error")
	}
}

func TestClientURI(t *testing.T) {
	clientUUID := uuid.NewString()
	data, err := vmess.MarshalProtocolData(vmess.ProtocolData{
		CertPath:   "/etc/obscura/certs/vpn-main.crt",
		KeyPath:    "/etc/obscura/certs/vpn-main.key",
		ServerName: "example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &vmess.Adapter{}
	vpn := domain.VPNConfig{
		Name: "main", Protocol: "vmess", Tag: "vpn-main", Enabled: true,
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: data,
	}
	client := domain.ClientConfig{Name: "phone", Password: clientUUID, Enabled: true}
	uri, err := adapter.ClientURI(vpn, []domain.ClientConfig{client}, client, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(uri) < 8 || uri[:8] != "vmess://" {
		t.Fatalf("unexpected uri: %q", uri)
	}
	payload, err := base64.StdEncoding.DecodeString(uri[8:])
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]string
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["allowInsecure"] != "1" {
		t.Fatalf("expected allowInsecure=1 in payload, got %#v", decoded)
	}
}

func TestClientURI_errors(t *testing.T) {
	adapter := &vmess.Adapter{}
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
	data, err := vmess.MarshalProtocolData(vmess.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &vmess.Adapter{}
	vpn := domain.VPNConfig{
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: data,
	}
	client := domain.ClientConfig{Name: "phone", Password: uuid.NewString(), Enabled: true}
	qr, err := adapter.ClientQRContent(vpn, []domain.ClientConfig{client}, client, "example.com")
	if err != nil || !strings.HasPrefix(qr, "vmess://") {
		t.Fatalf("ClientQRContent() = %q, %v", qr, err)
	}
}
