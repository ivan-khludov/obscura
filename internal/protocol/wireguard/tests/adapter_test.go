package wireguard_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/wireguard"
)

func TestAdapter_metadata(t *testing.T) {
	a := &wireguard.Adapter{}
	if a.Type() != "wireguard" {
		t.Fatalf("Type() = %q", a.Type())
	}
	def := a.DefaultListen()
	if def.Listen != "0.0.0.0" || def.ListenPort != 51820 {
		t.Fatalf("DefaultListen() = %#v", def)
	}
	if len(a.SupportedListenFields()) == 0 {
		t.Fatal("expected listen fields")
	}
	if a.UsesInbound() {
		t.Fatal("expected UsesInbound false")
	}
	if len(a.FirewallProtos()) != 1 || a.FirewallProtos()[0] != "udp" {
		t.Fatalf("FirewallProtos() = %v", a.FirewallProtos())
	}
}

func TestAdapter_RenderInbound(t *testing.T) {
	_, err := (&wireguard.Adapter{}).RenderInbound(domain.VPNConfig{}, nil)
	if err == nil || err.Error() != "wireguard does not use inbounds" {
		t.Fatalf("RenderInbound() err = %v", err)
	}
}

func TestAdapter_RouteExtensions(t *testing.T) {
	rules, err := (&wireguard.Adapter{}).RouteExtensions(domain.VPNConfig{Tag: "vpn-wg"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0]["inbound"] != "vpn-wg" || rules[0]["outbound"] != "direct" {
		t.Fatalf("unexpected rule: %#v", rules[0])
	}
}

func TestAdapter_AdditionalInbounds(t *testing.T) {
	inbounds, err := (&wireguard.Adapter{}).AdditionalInbounds(domain.VPNConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if inbounds != nil {
		t.Fatalf("AdditionalInbounds() = %#v", inbounds)
	}
}

func TestValidateVPN_errors(t *testing.T) {
	adapter := &wireguard.Adapter{}
	serverPriv, serverPub := mustKeypair(t)
	clientPriv, clientPub := mustKeypair(t)
	raw := mustProtocolData(t, serverPriv, serverPub, wireguard.ProtocolData{})
	listen := domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 51820}
	validClient := domain.ClientConfig{Name: "phone", Username: clientPub, Password: clientPriv, Enabled: true}
	validVPN := domain.VPNConfig{Name: "wg", Tag: "vpn-wg", Listen: listen, ProtocolData: raw}

	if err := adapter.ValidateVPN(domain.VPNConfig{Tag: "t", Listen: listen, ProtocolData: raw}, []domain.ClientConfig{validClient}); err == nil {
		t.Fatal("expected name error")
	}
	if err := adapter.ValidateVPN(domain.VPNConfig{Name: "wg", Listen: listen, ProtocolData: raw}, []domain.ClientConfig{validClient}); err == nil {
		t.Fatal("expected tag error")
	}
	if err := adapter.ValidateVPN(domain.VPNConfig{Name: "wg", Tag: "t", Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 0}, ProtocolData: raw}, []domain.ClientConfig{validClient}); err == nil {
		t.Fatal("expected listen error")
	}
	if err := adapter.ValidateVPN(domain.VPNConfig{Name: "wg", Tag: "t", Listen: listen, ProtocolData: []byte("{")}, []domain.ClientConfig{validClient}); err == nil {
		t.Fatal("expected parse error")
	}
	badOpts, _ := wireguard.MarshalProtocolData(wireguard.ProtocolData{Address: []string{"10.8.0.1/24"}})
	if err := adapter.ValidateVPN(domain.VPNConfig{Name: "wg", Tag: "t", Listen: listen, ProtocolData: badOpts}, []domain.ClientConfig{validClient}); err == nil {
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
	adapter := &wireguard.Adapter{}
	serverPriv, serverPub := mustKeypair(t)
	clientPriv, clientPub := mustKeypair(t)
	raw := mustProtocolData(t, serverPriv, serverPub, wireguard.ProtocolData{})
	vpn := domain.VPNConfig{
		Name: "wg", Tag: "vpn-wg",
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 51820},
		ProtocolData: raw,
	}
	clients := []domain.ClientConfig{
		{Name: "disabled", Enabled: false},
		{Name: "phone", Username: clientPub, Password: clientPriv, Enabled: true},
	}
	if err := adapter.ValidateVPN(vpn, clients); err != nil {
		t.Fatal(err)
	}
}

func TestValidateClient(t *testing.T) {
	adapter := &wireguard.Adapter{}
	priv, pub := mustKeypair(t)

	if err := adapter.ValidateClient(domain.ClientConfig{Username: pub, Password: priv}); err != nil {
		t.Fatalf("valid client: %v", err)
	}
	if err := adapter.ValidateClient(domain.ClientConfig{Username: pub}); err == nil || !strings.Contains(err.Error(), "private key is required") {
		t.Fatalf("missing password: %v", err)
	}
	if err := adapter.ValidateClient(domain.ClientConfig{Password: priv}); err == nil || !strings.Contains(err.Error(), "public key is required") {
		t.Fatalf("missing username: %v", err)
	}
	if err := adapter.ValidateClient(domain.ClientConfig{Username: pub, Password: "!!!"}); err == nil || !strings.Contains(err.Error(), "private key:") {
		t.Fatalf("invalid private key: %v", err)
	}
	if err := adapter.ValidateClient(domain.ClientConfig{Username: "!!!", Password: priv}); err == nil || !strings.Contains(err.Error(), "public key:") {
		t.Fatalf("invalid public key: %v", err)
	}
	wrongPub, _ := mustKeypair(t)
	if err := adapter.ValidateClient(domain.ClientConfig{Username: wrongPub, Password: priv}); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatch: %v", err)
	}
}

func TestRenderEndpoints_Golden(t *testing.T) {
	serverPriv, serverPub := mustKeypair(t)
	client := testClient(t, "phone")
	raw := mustProtocolData(t, serverPriv, serverPub, wireguard.ProtocolData{})
	adapter := &wireguard.Adapter{}
	got, err := adapter.RenderEndpoints(testVPN(t, raw), []domain.ClientConfig{client})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(got))
	}
	assertGolden(t, "../testdata/wireguard_endpoint.golden.json", got[0])
}

func TestRenderEndpoints_MultiPeer(t *testing.T) {
	serverPriv, serverPub := mustKeypair(t)
	raw := mustProtocolData(t, serverPriv, serverPub, wireguard.ProtocolData{})
	adapter := &wireguard.Adapter{}
	clients := []domain.ClientConfig{
		testClient(t, "a"),
		testClient(t, "b"),
	}
	got, err := adapter.RenderEndpoints(testVPN(t, raw), clients)
	if err != nil {
		t.Fatal(err)
	}
	peers, ok := got[0]["peers"].([]map[string]any)
	if !ok {
		t.Fatalf("peers type: %T", got[0]["peers"])
	}
	if len(peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(peers))
	}
}

func TestRenderEndpoints_validationError(t *testing.T) {
	adapter := &wireguard.Adapter{}
	_, err := adapter.RenderEndpoints(domain.VPNConfig{}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClientURI(t *testing.T) {
	serverPriv, serverPub := mustKeypair(t)
	_, pskPub := mustKeypair(t)
	client := testClient(t, "phone")
	raw := mustProtocolData(t, serverPriv, serverPub, wireguard.ProtocolData{
		PeerPreSharedKey: pskPub,
	})
	adapter := &wireguard.Adapter{}
	vpn := testVPN(t, raw)
	uri, err := adapter.ClientURI(vpn, []domain.ClientConfig{client}, client, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(uri, "wireguard://") {
		t.Fatalf("unexpected uri: %q", uri)
	}
	if !strings.Contains(uri, "presharedkey=") {
		t.Fatalf("expected preshared key in uri: %q", uri)
	}
	if !strings.Contains(uri, "keepalive=25") || !strings.Contains(uri, "mtu=1408") {
		t.Fatalf("expected default keepalive/mtu: %q", uri)
	}
	if !strings.Contains(uri, "#phone") {
		t.Fatalf("expected fragment: %q", uri)
	}
}

func TestClientURI_customMTUKeepalive(t *testing.T) {
	serverPriv, serverPub := mustKeypair(t)
	client := testClient(t, "phone")
	raw := mustProtocolData(t, serverPriv, serverPub, wireguard.ProtocolData{
		MTU:                             1500,
		PeerPersistentKeepaliveInterval: 60,
	})
	adapter := &wireguard.Adapter{}
	uri, err := adapter.ClientURI(testVPN(t, raw), []domain.ClientConfig{client}, client, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(uri, "keepalive=60") || !strings.Contains(uri, "mtu=1500") {
		t.Fatalf("expected custom keepalive/mtu: %q", uri)
	}
}

func TestClientURI_errors(t *testing.T) {
	adapter := &wireguard.Adapter{}
	serverPriv, serverPub := mustKeypair(t)
	raw := mustProtocolData(t, serverPriv, serverPub, wireguard.ProtocolData{})
	vpn := testVPN(t, raw)
	client := testClient(t, "phone")

	if _, err := adapter.ClientURI(vpn, nil, domain.ClientConfig{}, "host"); err == nil {
		t.Fatal("expected validate client error")
	}
	if _, err := adapter.ClientURI(domain.VPNConfig{ProtocolData: []byte("{")}, []domain.ClientConfig{client}, client, "host"); err == nil {
		t.Fatal("expected parse error")
	}
	if _, err := adapter.ClientURI(vpn, []domain.ClientConfig{client}, domain.ClientConfig{Name: "missing", Username: client.Username, Password: client.Password, Enabled: true}, "host"); err == nil {
		t.Fatal("expected tunnel ip error")
	}
}

func TestClientQRContent(t *testing.T) {
	serverPriv, serverPub := mustKeypair(t)
	_, pskPub := mustKeypair(t)
	client := testClient(t, "phone")
	raw := mustProtocolData(t, serverPriv, serverPub, wireguard.ProtocolData{
		PeerPreSharedKey:                pskPub,
		PeerPersistentKeepaliveInterval: 60,
		MTU:                             1500,
	})
	adapter := &wireguard.Adapter{}
	conf, err := adapter.ClientQRContent(testVPN(t, raw), []domain.ClientConfig{client}, client, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(conf, "[Interface]") {
		t.Fatalf("expected conf, got %q", conf)
	}
	if !strings.Contains(conf, "PresharedKey = ") {
		t.Fatal("expected preshared key in conf")
	}
	if !strings.Contains(conf, "MTU = 1500") || !strings.Contains(conf, "PersistentKeepalive = 60") {
		t.Fatalf("expected custom mtu/keepalive: %q", conf)
	}
}

func TestValidateClient_publicKeyDeriveError(t *testing.T) {
	restore := wireguard.SetPublicKeyFromPrivateFuncForTest(func(string) (string, error) {
		return "", errors.New("derive failed")
	})
	t.Cleanup(restore)
	priv, pub := mustKeypair(t)
	adapter := &wireguard.Adapter{}
	if err := adapter.ValidateClient(domain.ClientConfig{Username: pub, Password: priv}); err == nil || !strings.Contains(err.Error(), "derive failed") {
		t.Fatalf("expected derive error, got %v", err)
	}
}

func TestClientQRContent_tunnelIPError(t *testing.T) {
	adapter := &wireguard.Adapter{}
	serverPriv, serverPub := mustKeypair(t)
	raw := mustProtocolData(t, serverPriv, serverPub, wireguard.ProtocolData{})
	client := testClient(t, "phone")
	if _, err := adapter.ClientQRContent(testVPN(t, raw), []domain.ClientConfig{client}, domain.ClientConfig{Name: "missing", Username: client.Username, Password: client.Password, Enabled: true}, "host"); err == nil {
		t.Fatal("expected tunnel ip error")
	}
}

func TestClientQRContent_errors(t *testing.T) {
	adapter := &wireguard.Adapter{}
	serverPriv, serverPub := mustKeypair(t)
	raw := mustProtocolData(t, serverPriv, serverPub, wireguard.ProtocolData{})
	client := testClient(t, "phone")

	if _, err := adapter.ClientQRContent(testVPN(t, raw), nil, domain.ClientConfig{}, "host"); err == nil {
		t.Fatal("expected validate client error")
	}
	if _, err := adapter.ClientQRContent(domain.VPNConfig{ProtocolData: []byte("{")}, []domain.ClientConfig{client}, client, "host"); err == nil {
		t.Fatal("expected parse error")
	}
}
