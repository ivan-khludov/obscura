package shadowsocks_test

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/shadowsocks"
)

func TestAdapter_metadata(t *testing.T) {
	a := &shadowsocks.Adapter{}
	if a.Type() != "shadowsocks" {
		t.Fatalf("Type() = %q", a.Type())
	}
	def := a.DefaultListen()
	if def.Listen != "0.0.0.0" || def.ListenPort != 8388 {
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
	ep, err := a.RenderEndpoints(domain.VPNConfig{}, nil)
	if err != nil || ep != nil {
		t.Fatalf("RenderEndpoints() = %v, %v", ep, err)
	}
}

func TestParseProtocolData(t *testing.T) {
	empty, err := shadowsocks.ParseProtocolData(nil)
	if err != nil || empty.Method != "" {
		t.Fatalf("empty parse: %#v, %v", empty, err)
	}
	got, err := shadowsocks.ParseProtocolData([]byte(`{"method":"2022-blake3-aes-128-gcm"}`))
	if err != nil || got.Method != "2022-blake3-aes-128-gcm" {
		t.Fatalf("parse: %#v, %v", got, err)
	}
	_, err = shadowsocks.ParseProtocolData([]byte(`{`))
	if err == nil || !strings.Contains(err.Error(), "parse shadowsocks protocol data") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestMarshalProtocolData(t *testing.T) {
	raw, err := shadowsocks.MarshalProtocolData(shadowsocks.ProtocolData{
		Method: "2022-blake3-aes-128-gcm",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "2022-blake3-aes-128-gcm") {
		t.Fatalf("unexpected marshal: %s", raw)
	}
}

func TestUsersFromClients_skipsDisabled(t *testing.T) {
	users := shadowsocks.UsersFromClients([]domain.ClientConfig{
		{Name: "enabled", Password: "p", Enabled: true},
		{Name: "disabled", Password: "p", Enabled: false},
	})
	if len(users) != 1 || users[0]["name"] != "enabled" {
		t.Fatalf("unexpected users: %#v", users)
	}
}

func TestRenderInbound_Golden(t *testing.T) {
	data, err := shadowsocks.MarshalProtocolData(shadowsocks.ProtocolData{
		Method:         "2022-blake3-aes-128-gcm",
		ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &shadowsocks.Adapter{}
	vpn := domain.VPNConfig{
		Name: "main", Protocol: "shadowsocks", Tag: "vpn-main", Enabled: true,
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8388},
		ProtocolData: data,
	}
	clients := []domain.ClientConfig{
		{Name: "phone", Username: "phone", Password: "PCD2Z4o12bKUoFa3cC97Hw==", Enabled: true},
	}
	got, err := adapter.RenderInbound(vpn, clients)
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "../testdata/shadowsocks_inbound.golden.json", got)
}

func TestClientURI(t *testing.T) {
	data, err := shadowsocks.MarshalProtocolData(shadowsocks.ProtocolData{
		Method:         "2022-blake3-aes-128-gcm",
		ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &shadowsocks.Adapter{}
	vpn := domain.VPNConfig{
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8388},
		ProtocolData: data,
	}
	client := domain.ClientConfig{
		Name: "phone", Username: "phone", Password: "PCD2Z4o12bKUoFa3cC97Hw==", Enabled: true,
	}
	uri, err := adapter.ClientURI(vpn, []domain.ClientConfig{client}, client, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if uri[:5] != "ss://" {
		t.Fatalf("unexpected uri: %s", uri)
	}
}

func TestClientURI_Plugin(t *testing.T) {
	data, err := shadowsocks.MarshalProtocolData(shadowsocks.ProtocolData{
		Method: "2022-blake3-aes-128-gcm", ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
		Plugin: "obfs-local", PluginOpts: shadowsocks.DefaultObfsPluginOpts,
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &shadowsocks.Adapter{}
	vpn := domain.VPNConfig{
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8388},
		ProtocolData: data,
	}
	client := domain.ClientConfig{
		Name: "phone", Password: "PCD2Z4o12bKUoFa3cC97Hw==", Enabled: true,
	}
	uri, err := adapter.ClientURI(vpn, []domain.ClientConfig{client}, client, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(uri, "plugin=obfs-local") {
		t.Fatalf("expected plugin in uri, got %s", uri)
	}
}

func TestClientURI_errors(t *testing.T) {
	adapter := &shadowsocks.Adapter{}
	vpn := domain.VPNConfig{
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8388},
		ProtocolData: []byte(`{`),
	}
	client := domain.ClientConfig{Name: "phone", Password: "PCD2Z4o12bKUoFa3cC97Hw==", Enabled: true}
	if _, err := adapter.ClientURI(vpn, nil, domain.ClientConfig{}, "host"); err == nil {
		t.Fatal("expected validate client error")
	}
	if _, err := adapter.ClientURI(vpn, nil, client, "host"); err == nil {
		t.Fatal("expected parse protocol data error")
	}
	data, _ := shadowsocks.MarshalProtocolData(shadowsocks.ProtocolData{
		Method: "2022-blake3-aes-128-gcm", ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
	})
	vpn.ProtocolData = data
	if _, err := adapter.ClientURI(vpn, nil, domain.ClientConfig{Name: "x", Password: "not-valid-base64!!!", Enabled: true}, "host"); err == nil {
		t.Fatal("expected validate key error")
	}
}

func TestClientQRContent(t *testing.T) {
	data, err := shadowsocks.MarshalProtocolData(shadowsocks.ProtocolData{
		Method: "2022-blake3-aes-128-gcm", ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &shadowsocks.Adapter{}
	vpn := domain.VPNConfig{
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8388},
		ProtocolData: data,
	}
	client := domain.ClientConfig{Name: "phone", Password: "PCD2Z4o12bKUoFa3cC97Hw==", Enabled: true}
	qr, err := adapter.ClientQRContent(vpn, []domain.ClientConfig{client}, client, "example.com")
	if err != nil || !strings.HasPrefix(qr, "ss://") {
		t.Fatalf("ClientQRContent() = %q, %v", qr, err)
	}
}

func TestRenderInbound_Multiplex(t *testing.T) {
	data, _ := shadowsocks.MarshalProtocolData(shadowsocks.ProtocolData{
		Method: "2022-blake3-aes-128-gcm", ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
		Multiplex: true, MultiplexPadding: true,
	})
	adapter := &shadowsocks.Adapter{}
	vpn := domain.VPNConfig{
		Name: "main", Tag: "vpn-main",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8388},
		ProtocolData: data,
	}
	clients := []domain.ClientConfig{
		{Name: "phone", Password: "PCD2Z4o12bKUoFa3cC97Hw==", Enabled: true},
	}
	got, err := adapter.RenderInbound(vpn, clients)
	if err != nil {
		t.Fatal(err)
	}
	multiplex, ok := got["multiplex"].(map[string]any)
	if !ok || multiplex["enabled"] != true || multiplex["padding"] != true {
		t.Fatalf("unexpected multiplex: %#v", got["multiplex"])
	}
}

func TestRenderInbound_MultiplexNoPadding(t *testing.T) {
	data, _ := shadowsocks.MarshalProtocolData(shadowsocks.ProtocolData{
		Method: "2022-blake3-aes-128-gcm", ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
		Multiplex: true,
	})
	adapter := &shadowsocks.Adapter{}
	vpn := domain.VPNConfig{
		Name: "main", Tag: "vpn-main",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8388},
		ProtocolData: data,
	}
	clients := []domain.ClientConfig{
		{Name: "phone", Password: "PCD2Z4o12bKUoFa3cC97Hw==", Enabled: true},
	}
	got, err := adapter.RenderInbound(vpn, clients)
	if err != nil {
		t.Fatal(err)
	}
	multiplex, ok := got["multiplex"].(map[string]any)
	if !ok || multiplex["enabled"] != true {
		t.Fatalf("unexpected multiplex: %#v", got["multiplex"])
	}
	if _, hasPadding := multiplex["padding"]; hasPadding {
		t.Fatalf("expected no padding key: %#v", multiplex)
	}
}

func TestRenderInbound_PluginNotOnInbound(t *testing.T) {
	data, _ := shadowsocks.MarshalProtocolData(shadowsocks.ProtocolData{
		Method: "2022-blake3-aes-128-gcm", ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
		Plugin: "obfs-local", PluginOpts: shadowsocks.DefaultObfsPluginOpts,
	})
	adapter := &shadowsocks.Adapter{}
	vpn := domain.VPNConfig{
		Name: "main", Tag: "vpn-main",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8388},
		ProtocolData: data,
	}
	clients := []domain.ClientConfig{
		{Name: "phone", Password: "PCD2Z4o12bKUoFa3cC97Hw==", Enabled: true},
	}
	got, err := adapter.RenderInbound(vpn, clients)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["plugin"]; ok {
		t.Fatalf("plugin must not be rendered on inbound: %#v", got)
	}
}

func TestRenderInbound_validationError(t *testing.T) {
	adapter := &shadowsocks.Adapter{}
	_, err := adapter.RenderInbound(domain.VPNConfig{}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAdditionalInbounds_noShadowTLS(t *testing.T) {
	data, _ := shadowsocks.MarshalProtocolData(shadowsocks.ProtocolData{
		Method: "2022-blake3-aes-128-gcm", ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
	})
	adapter := &shadowsocks.Adapter{}
	vpn := domain.VPNConfig{
		Name: "main", Tag: "vpn-main",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8388},
		ProtocolData: data,
	}
	extras, err := adapter.AdditionalInbounds(vpn, nil)
	if err != nil || extras != nil {
		t.Fatalf("AdditionalInbounds() = %v, %v", extras, err)
	}
}

func TestAdditionalInbounds_parseError(t *testing.T) {
	adapter := &shadowsocks.Adapter{}
	vpn := domain.VPNConfig{ProtocolData: []byte(`{`)}
	_, err := adapter.AdditionalInbounds(vpn, nil)
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestAdditionalInbounds_ShadowTLS(t *testing.T) {
	data, _ := shadowsocks.MarshalProtocolData(shadowsocks.ProtocolData{
		Method: "2022-blake3-aes-128-gcm", ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
		ShadowTLS: true, ShadowTLSPassword: "st-secret", ShadowTLSHandshake: "www.bing.com",
		ShadowTLSBackendPort: 38443, ShadowTLSStrictMode: true,
		ShadowTLSVersion: 2, ShadowTLSHandshakePort: 8443,
	})
	adapter := &shadowsocks.Adapter{}
	vpn := domain.VPNConfig{
		Name: "main", Tag: "vpn-main",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: data,
	}
	clients := []domain.ClientConfig{
		{Name: "phone", Password: "PCD2Z4o12bKUoFa3cC97Hw==", Enabled: true},
		{Name: "disabled", Password: "PCD2Z4o12bKUoFa3cC97Hw==", Enabled: false},
	}
	ss, err := adapter.RenderInbound(vpn, clients)
	if err != nil {
		t.Fatal(err)
	}
	if ss["listen"] != "127.0.0.1" {
		t.Fatalf("expected internal listen, got %#v", ss["listen"])
	}
	if ss["listen_port"] != 38443 {
		t.Fatalf("expected backend port 38443, got %#v", ss["listen_port"])
	}
	extras, err := adapter.AdditionalInbounds(vpn, clients)
	if err != nil {
		t.Fatal(err)
	}
	if len(extras) != 1 || extras[0]["type"] != "shadowtls" || extras[0]["detour"] != "vpn-main" {
		t.Fatalf("unexpected shadowtls inbound: %#v", extras)
	}
	if extras[0]["version"] != 2 {
		t.Fatalf("expected shadowtls version 2, got %#v", extras[0]["version"])
	}
	handshake, ok := extras[0]["handshake"].(map[string]any)
	if !ok || handshake["server_port"] != 8443 {
		t.Fatalf("unexpected handshake: %#v", extras[0]["handshake"])
	}
	users, ok := extras[0]["users"].([]map[string]string)
	if !ok {
		if u, ok := extras[0]["users"].([]any); ok {
			if len(u) != 1 {
				t.Fatalf("expected one shadowtls user, got %#v", extras[0]["users"])
			}
		} else {
			t.Fatalf("unexpected users type: %T", extras[0]["users"])
		}
	} else if len(users) != 1 {
		t.Fatalf("expected one shadowtls user, got %#v", users)
	}
}

func TestRenderInbound_ShadowTLSBackendPortFallback(t *testing.T) {
	tests := []struct {
		name       string
		listenPort int
		wantPort   int
	}{
		{name: "public plus offset", listenPort: 443, wantPort: 10443},
		{name: "overflow fallback", listenPort: 56000, wantPort: 36000},
		{name: "collision increment", listenPort: 20000, wantPort: 30000},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, _ := shadowsocks.MarshalProtocolData(shadowsocks.ProtocolData{
				Method: "2022-blake3-aes-128-gcm", ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
				ShadowTLS: true, ShadowTLSPassword: "st-secret", ShadowTLSHandshake: "www.bing.com",
			})
			adapter := &shadowsocks.Adapter{}
			vpn := domain.VPNConfig{
				Name: "main", Tag: "vpn-main",
				Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: tc.listenPort},
				ProtocolData: data,
			}
			clients := []domain.ClientConfig{
				{Name: "phone", Password: "PCD2Z4o12bKUoFa3cC97Hw==", Enabled: true},
			}
			got, err := adapter.RenderInbound(vpn, clients)
			if err != nil {
				t.Fatal(err)
			}
			if got["listen_port"] != tc.wantPort {
				t.Fatalf("listen_port = %v, want %d", got["listen_port"], tc.wantPort)
			}
		})
	}
}

func TestValidateVPN_errors(t *testing.T) {
	adapter := &shadowsocks.Adapter{}
	validData, _ := shadowsocks.MarshalProtocolData(shadowsocks.ProtocolData{
		Method: "2022-blake3-aes-128-gcm", ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
	})
	listen := domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8388}
	client := domain.ClientConfig{Name: "phone", Password: "PCD2Z4o12bKUoFa3cC97Hw==", Enabled: true}

	if err := adapter.ValidateVPN(domain.VPNConfig{Tag: "t", Listen: listen, ProtocolData: validData}, []domain.ClientConfig{client}); err == nil {
		t.Fatal("expected name error")
	}
	if err := adapter.ValidateVPN(domain.VPNConfig{Name: "n", Listen: listen, ProtocolData: validData}, []domain.ClientConfig{client}); err == nil {
		t.Fatal("expected tag error")
	}
	if err := adapter.ValidateVPN(domain.VPNConfig{Name: "n", Tag: "t", Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 0}, ProtocolData: validData}, []domain.ClientConfig{client}); err == nil {
		t.Fatal("expected listen error")
	}
	if err := adapter.ValidateVPN(domain.VPNConfig{Name: "n", Tag: "t", Listen: listen, ProtocolData: []byte(`{`)}, []domain.ClientConfig{client}); err == nil {
		t.Fatal("expected parse error")
	}
	if err := adapter.ValidateVPN(domain.VPNConfig{Name: "n", Tag: "t", Listen: listen, ProtocolData: []byte(`{}`)}, []domain.ClientConfig{client}); err == nil {
		t.Fatal("expected method error")
	}
}

func TestValidateVPN_Chacha20MultiUserRejected(t *testing.T) {
	data, _ := shadowsocks.MarshalProtocolData(shadowsocks.ProtocolData{
		Method: "2022-blake3-chacha20-poly1305", ServerPassword: "ZDg0ZWYxMmQwYzJhNGQzZTg0NTY3YzUyMjI5ZjUwZTY=",
	})
	adapter := &shadowsocks.Adapter{}
	vpn := domain.VPNConfig{
		Name: "main", Tag: "vpn-main",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8388},
		ProtocolData: data,
	}
	clients := []domain.ClientConfig{
		{Name: "phone", Password: "YjEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", Enabled: true},
	}
	err := adapter.ValidateVPN(vpn, clients)
	if err == nil || !strings.Contains(err.Error(), "multi-user") {
		t.Fatalf("expected multi-user error, got %v", err)
	}
}

func TestValidateVPN_invalidServerPassword(t *testing.T) {
	data, _ := shadowsocks.MarshalProtocolData(shadowsocks.ProtocolData{
		Method: "2022-blake3-aes-128-gcm", ServerPassword: "short",
	})
	adapter := &shadowsocks.Adapter{}
	vpn := domain.VPNConfig{
		Name: "main", Tag: "vpn-main",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8388},
		ProtocolData: data,
	}
	client := domain.ClientConfig{Name: "phone", Password: "PCD2Z4o12bKUoFa3cC97Hw==", Enabled: true}
	err := adapter.ValidateVPN(vpn, []domain.ClientConfig{client})
	if err == nil || !strings.Contains(err.Error(), "server_password") {
		t.Fatalf("expected server_password error, got %v", err)
	}
}

func TestValidateVPN_validateOptionsError(t *testing.T) {
	data, _ := shadowsocks.MarshalProtocolData(shadowsocks.ProtocolData{
		Method: "2022-blake3-aes-128-gcm", ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
		Plugin: "unknown-plugin", PluginOpts: "x",
	})
	adapter := &shadowsocks.Adapter{}
	vpn := domain.VPNConfig{
		Name: "main", Tag: "vpn-main",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8388},
		ProtocolData: data,
	}
	client := domain.ClientConfig{Name: "phone", Password: "PCD2Z4o12bKUoFa3cC97Hw==", Enabled: true}
	if err := adapter.ValidateVPN(vpn, []domain.ClientConfig{client}); err == nil {
		t.Fatal("expected validate options error")
	}
}

func TestValidateVPN_shadowTLSBackendPortConflict(t *testing.T) {
	data, _ := shadowsocks.MarshalProtocolData(shadowsocks.ProtocolData{
		Method: "2022-blake3-aes-128-gcm", ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
		ShadowTLS: true, ShadowTLSPassword: "secret", ShadowTLSHandshake: "www.bing.com",
		ShadowTLSBackendPort: 443,
	})
	adapter := &shadowsocks.Adapter{}
	vpn := domain.VPNConfig{
		Name: "main", Tag: "vpn-main",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: data,
	}
	client := domain.ClientConfig{Name: "phone", Password: "PCD2Z4o12bKUoFa3cC97Hw==", Enabled: true}
	err := adapter.ValidateVPN(vpn, []domain.ClientConfig{client})
	if err == nil || !strings.Contains(err.Error(), "backend port must differ") {
		t.Fatalf("expected backend port conflict, got %v", err)
	}
}

func TestValidateVPN_RequiresClient(t *testing.T) {
	data, _ := shadowsocks.MarshalProtocolData(shadowsocks.ProtocolData{
		Method: "2022-blake3-aes-128-gcm", ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
	})
	adapter := &shadowsocks.Adapter{}
	vpn := domain.VPNConfig{
		Name: "main", Tag: "vpn-main",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8388},
		ProtocolData: data,
	}
	if err := adapter.ValidateVPN(vpn, nil); err == nil {
		t.Fatal("expected error without clients")
	}
}

func TestValidateVPN_invalidClientPassword(t *testing.T) {
	data, _ := shadowsocks.MarshalProtocolData(shadowsocks.ProtocolData{
		Method: "2022-blake3-aes-128-gcm", ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
	})
	adapter := &shadowsocks.Adapter{}
	vpn := domain.VPNConfig{
		Name: "main", Tag: "vpn-main",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8388},
		ProtocolData: data,
	}
	client := domain.ClientConfig{Name: "phone", Password: "bad-key", Enabled: true}
	if err := adapter.ValidateVPN(vpn, []domain.ClientConfig{client}); err == nil {
		t.Fatal("expected client password validation error")
	}
}

func TestRenderInbound_parseErrorAfterValidate(t *testing.T) {
	data, err := shadowsocks.MarshalProtocolData(shadowsocks.ProtocolData{
		Method: "2022-blake3-aes-128-gcm", ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &shadowsocks.Adapter{}
	vpn := domain.VPNConfig{
		Name: "main", Tag: "vpn-main",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8388},
		ProtocolData: data,
	}
	clients := []domain.ClientConfig{{Name: "phone", Password: "PCD2Z4o12bKUoFa3cC97Hw==", Enabled: true}}
	reset := shadowsocks.SetParseProtocolDataForTest(func([]byte) (shadowsocks.ProtocolData, error) {
		return shadowsocks.ProtocolData{}, errors.New("parse shadowsocks protocol data: boom")
	})
	defer reset()
	_, err = adapter.RenderInbound(vpn, clients)
	if err == nil || !strings.Contains(err.Error(), "parse shadowsocks protocol data") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestValidateVPN_invalidClientName(t *testing.T) {
	data, _ := shadowsocks.MarshalProtocolData(shadowsocks.ProtocolData{
		Method: "2022-blake3-aes-128-gcm", ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
	})
	adapter := &shadowsocks.Adapter{}
	vpn := domain.VPNConfig{
		Name: "main", Tag: "vpn-main",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8388},
		ProtocolData: data,
	}
	client := domain.ClientConfig{Name: "", Password: "PCD2Z4o12bKUoFa3cC97Hw==", Enabled: true}
	if err := adapter.ValidateVPN(vpn, []domain.ClientConfig{client}); err == nil {
		t.Fatal("expected client name validation error")
	}
}

func TestAdditionalInbounds_validateVPNError(t *testing.T) {
	data, _ := shadowsocks.MarshalProtocolData(shadowsocks.ProtocolData{
		Method: "2022-blake3-aes-128-gcm", ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
		ShadowTLS: true, ShadowTLSPassword: "secret", ShadowTLSHandshake: "www.bing.com",
	})
	adapter := &shadowsocks.Adapter{}
	vpn := domain.VPNConfig{
		Name: "main", Tag: "vpn-main",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: data,
	}
	_, err := adapter.AdditionalInbounds(vpn, nil)
	if err == nil {
		t.Fatal("expected validation error without clients")
	}
}

func TestAdditionalInbounds_defaultShadowTLSFields(t *testing.T) {
	data := shadowsocks.ProtocolData{
		Method: "2022-blake3-aes-128-gcm", ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
		ShadowTLS: true, ShadowTLSPassword: "secret", ShadowTLSHandshake: "www.bing.com",
	}
	if shadowsocks.ShadowTLSVersionForTest(data) != 3 {
		t.Fatal("expected default shadowtls version 3")
	}
	if shadowsocks.ShadowTLSHandshakePortForTest(data) != shadowsocks.DefaultShadowTLSHandshakePort {
		t.Fatal("expected default handshake port")
	}
	raw, _ := shadowsocks.MarshalProtocolData(data)
	adapter := &shadowsocks.Adapter{}
	vpn := domain.VPNConfig{
		Name: "main", Tag: "vpn-main",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: raw,
	}
	clients := []domain.ClientConfig{{Name: "phone", Password: "PCD2Z4o12bKUoFa3cC97Hw==", Enabled: true}}
	extras, err := adapter.AdditionalInbounds(vpn, clients)
	if err != nil {
		t.Fatal(err)
	}
	if extras[0]["version"] != 3 {
		t.Fatalf("expected version 3, got %#v", extras[0]["version"])
	}
	handshake, ok := extras[0]["handshake"].(map[string]any)
	if !ok {
		t.Fatalf("unexpected handshake: %#v", extras[0]["handshake"])
	}
	switch sp := handshake["server_port"].(type) {
	case float64:
		if int(sp) != shadowsocks.DefaultShadowTLSHandshakePort {
			t.Fatalf("expected default handshake port, got %#v", handshake["server_port"])
		}
	case int:
		if sp != shadowsocks.DefaultShadowTLSHandshakePort {
			t.Fatalf("expected default handshake port, got %#v", handshake["server_port"])
		}
	default:
		t.Fatalf("unexpected server_port type %T", handshake["server_port"])
	}
}

func TestValidateClient(t *testing.T) {
	adapter := &shadowsocks.Adapter{}
	if err := adapter.ValidateClient(domain.ClientConfig{Name: "n", Password: "p"}); err != nil {
		t.Fatal(err)
	}
	if err := adapter.ValidateClient(domain.ClientConfig{Password: "p"}); err == nil {
		t.Fatal("expected name error")
	}
	if err := adapter.ValidateClient(domain.ClientConfig{Name: "n"}); err == nil {
		t.Fatal("expected password error")
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
