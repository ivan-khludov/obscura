package wireguard_test

import (
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/wireguard"
)

func TestRenderClientConf_defaults(t *testing.T) {
	serverPriv, serverPub := mustKeypair(t)
	client := testClient(t, "phone")
	data := wireguard.ProtocolData{
		PrivateKey: serverPriv,
		PublicKey:  serverPub,
		Address:    []string{"10.8.0.1/24"},
	}
	vpn := domain.VPNConfig{
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 51820},
	}
	conf := wireguard.RenderClientConf(vpn, data, client, "example.com", "10.8.0.2/32")
	if !strings.Contains(conf, "MTU = 1408") {
		t.Fatalf("expected default mtu: %q", conf)
	}
	if !strings.Contains(conf, "PersistentKeepalive = 25") {
		t.Fatalf("expected default keepalive: %q", conf)
	}
	if !strings.Contains(conf, "AllowedIPs = 0.0.0.0/0, ::/0") {
		t.Fatalf("expected default allowed ips: %q", conf)
	}
	if strings.Contains(conf, "PresharedKey") {
		t.Fatal("unexpected preshared key")
	}
}

func TestRenderClientConf_customAndPreshared(t *testing.T) {
	serverPriv, serverPub := mustKeypair(t)
	_, psk := mustKeypair(t)
	client := testClient(t, "phone")
	data := wireguard.ProtocolData{
		PrivateKey:                      serverPriv,
		PublicKey:                       serverPub,
		Address:                         []string{"10.8.0.1/24"},
		MTU:                             1500,
		PeerPersistentKeepaliveInterval: 60,
		PeerPreSharedKey:                psk,
		ClientAllowedIPs:                []string{"10.0.0.0/8"},
	}
	vpn := domain.VPNConfig{
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 51820},
	}
	conf := wireguard.RenderClientConf(vpn, data, client, "example.com", "10.8.0.2/32")
	if !strings.Contains(conf, "PresharedKey = "+psk) {
		t.Fatalf("expected preshared key: %q", conf)
	}
	if !strings.Contains(conf, "MTU = 1500") || !strings.Contains(conf, "PersistentKeepalive = 60") {
		t.Fatalf("expected custom mtu/keepalive: %q", conf)
	}
	if !strings.Contains(conf, "AllowedIPs = 10.0.0.0/8") {
		t.Fatalf("expected custom allowed ips: %q", conf)
	}
	if !strings.Contains(conf, "Endpoint = example.com:51820") {
		t.Fatalf("expected endpoint: %q", conf)
	}
}
