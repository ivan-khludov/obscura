package wireguard_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/wireguard"
)

func TestRenderEndpoint_allDialFields(t *testing.T) {
	serverPriv, serverPub := mustKeypair(t)
	_, psk := mustKeypair(t)
	adapter := &wireguard.Adapter{}
	fullData, err := wireguard.MarshalProtocolData(wireguard.ProtocolData{
		PrivateKey:                      serverPriv,
		PublicKey:                       serverPub,
		Address:                         []string{"10.8.0.1/24"},
		System:                          true,
		Name:                            "wg0",
		MTU:                             1500,
		UDPTimeout:                      "5m",
		Workers:                         2,
		PeerPreSharedKey:                psk,
		PeerPersistentKeepaliveInterval: 60,
		PeerReserved:                    []int{1, 2, 3},
		Detour:                          "direct",
		BindInterface:                   "eth0",
		Inet4BindAddress:                "192.0.2.1",
		Inet6BindAddress:                "2001:db8::1",
		BindAddressNoPort:               true,
		RoutingMark:                     "0x2",
		ReuseAddr:                       true,
		Netns:                           "netns1",
		ConnectTimeout:                  "30s",
		TCPFastOpen:                     true,
		TCPMultiPath:                    true,
		DisableTCPKeepAlive:             true,
		TCPKeepAlive:                    "15s",
		TCPKeepAliveInterval:            "30s",
		UDPFragment:                     true,
		DomainResolver:                  "local",
		NetworkStrategy:                 "default",
		NetworkType:                     []string{"wifi"},
		FallbackNetworkType:             []string{"cellular"},
		FallbackDelay:                   "300ms",
	})
	if err != nil {
		t.Fatal(err)
	}
	vpn := testVPN(t, fullData)
	client := testClient(t, "phone")
	got, err := adapter.RenderEndpoints(vpn, []domain.ClientConfig{client})
	if err != nil {
		t.Fatal(err)
	}
	ep := got[0]
	if ep["name"] != "wg0" || ep["system"] != true {
		t.Fatalf("name/system = %#v", ep)
	}
	if ep["mtu"] != 1500 {
		t.Fatalf("mtu = %#v", ep["mtu"])
	}
	if ep["udp_timeout"] != "5m" || ep["workers"] != 2 {
		t.Fatalf("udp_timeout/workers = %#v %#v", ep["udp_timeout"], ep["workers"])
	}
	if ep["detour"] != "direct" || ep["bind_interface"] != "eth0" {
		t.Fatalf("detour/bind_interface = %#v %#v", ep["detour"], ep["bind_interface"])
	}
	if ep["inet4_bind_address"] != "192.0.2.1" || ep["inet6_bind_address"] != "2001:db8::1" {
		t.Fatalf("bind addresses = %#v %#v", ep["inet4_bind_address"], ep["inet6_bind_address"])
	}
	if ep["bind_address_no_port"] != true || ep["routing_mark"] != "0x2" || ep["reuse_addr"] != true || ep["netns"] != "netns1" {
		t.Fatalf("bind/routing/netns = %#v", ep)
	}
	if ep["connect_timeout"] != "30s" || ep["domain_resolver"] != "local" || ep["network_strategy"] != "default" || ep["fallback_delay"] != "300ms" {
		t.Fatalf("timeouts/resolver = %#v", ep)
	}
	if ep["tcp_fast_open"] != true || ep["tcp_multi_path"] != true || ep["disable_tcp_keep_alive"] != true {
		t.Fatalf("tcp flags = %#v", ep)
	}
	if ep["tcp_keep_alive"] != "15s" || ep["tcp_keep_alive_interval"] != "30s" || ep["udp_fragment"] != true {
		t.Fatalf("tcp keepalive/udp = %#v", ep)
	}
	if nt, ok := ep["network_type"].([]string); !ok || len(nt) != 1 || nt[0] != "wifi" {
		t.Fatalf("network_type = %#v", ep["network_type"])
	}
	if fnt, ok := ep["fallback_network_type"].([]string); !ok || len(fnt) != 1 || fnt[0] != "cellular" {
		t.Fatalf("fallback_network_type = %#v", ep["fallback_network_type"])
	}
	peers, ok := ep["peers"].([]map[string]any)
	if !ok || len(peers) != 1 {
		t.Fatalf("peers = %#v", ep["peers"])
	}
	if peers[0]["pre_shared_key"] != psk {
		t.Fatalf("pre_shared_key = %#v", peers[0]["pre_shared_key"])
	}
	if peers[0]["persistent_keepalive_interval"] != 60 {
		t.Fatalf("keepalive = %#v", peers[0]["persistent_keepalive_interval"])
	}
	if reserved, ok := peers[0]["reserved"].([]int); !ok || len(reserved) != 3 {
		t.Fatalf("reserved = %#v", peers[0]["reserved"])
	}
}

func TestRenderEndpoints_addressExhausted(t *testing.T) {
	serverPriv, serverPub := mustKeypair(t)
	raw, err := wireguard.MarshalProtocolData(wireguard.ProtocolData{
		PrivateKey: serverPriv,
		PublicKey:  serverPub,
		Address:    []string{"10.8.0.1/30"},
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &wireguard.Adapter{}
	clients := []domain.ClientConfig{
		testClient(t, "a"),
		testClient(t, "b"),
		testClient(t, "c"),
	}
	_, err = adapter.RenderEndpoints(testVPN(t, raw), clients)
	if err == nil || !strings.Contains(err.Error(), "no available address") {
		t.Fatalf("expected exhausted error, got %v", err)
	}
}

func TestRenderEndpoints_parseErrorAfterValidate(t *testing.T) {
	serverPriv, serverPub := mustKeypair(t)
	raw := mustProtocolData(t, serverPriv, serverPub, wireguard.ProtocolData{})
	client := testClient(t, "phone")
	calls := 0
	restore := wireguard.SetParseProtocolDataHookForTest(func(b []byte) (wireguard.ProtocolData, error) {
		calls++
		if calls > 1 {
			return wireguard.ProtocolData{}, errors.New("parse failed")
		}
		return wireguard.ParseProtocolDataUnhooked(b)
	})
	t.Cleanup(restore)
	_, err := (&wireguard.Adapter{}).RenderEndpoints(testVPN(t, raw), []domain.ClientConfig{client})
	if err == nil || !strings.Contains(err.Error(), "parse failed") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestRenderEndpoint_minimalFields(t *testing.T) {
	serverPriv, serverPub := mustKeypair(t)
	raw := mustProtocolData(t, serverPriv, serverPub, wireguard.ProtocolData{})
	adapter := &wireguard.Adapter{}
	client := testClient(t, "phone")
	got, err := adapter.RenderEndpoints(testVPN(t, raw), []domain.ClientConfig{client})
	if err != nil {
		t.Fatal(err)
	}
	ep := got[0]
	if _, ok := ep["name"]; ok {
		t.Fatal("expected no name field")
	}
	if _, ok := ep["udp_timeout"]; ok {
		t.Fatal("expected no udp_timeout field")
	}
	if _, ok := ep["workers"]; ok {
		t.Fatal("expected no workers field")
	}
	peers := ep["peers"].([]map[string]any)
	if _, ok := peers[0]["pre_shared_key"]; ok {
		t.Fatal("expected no pre_shared_key")
	}
	if _, ok := peers[0]["reserved"]; ok {
		t.Fatal("expected no reserved field")
	}
}

func TestRenderPeers_disabledClientSkipped(t *testing.T) {
	serverPriv, serverPub := mustKeypair(t)
	data := wireguard.ProtocolData{
		PrivateKey: serverPriv,
		PublicKey:  serverPub,
		Address:    []string{"10.8.0.1/24"},
	}
	enabled := testClient(t, "phone")
	peers, err := wireguard.RenderPeersForTest(data, []domain.ClientConfig{
		{Name: "disabled", Enabled: false, Username: "x"},
		enabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
}

func TestRenderPeers_missingPublicKey(t *testing.T) {
	serverPriv, serverPub := mustKeypair(t)
	data := wireguard.ProtocolData{
		PrivateKey: serverPriv,
		PublicKey:  serverPub,
		Address:    []string{"10.8.0.1/24"},
	}
	clients := []domain.ClientConfig{
		{Name: "no-key", Password: "x", Enabled: true},
	}
	_, err := wireguard.RenderPeersForTest(data, clients)
	if err == nil || !strings.Contains(err.Error(), `"no-key"`) {
		t.Fatalf("expected public key error, got %v", err)
	}
}

func TestRenderPeers_addressExhausted(t *testing.T) {
	serverPriv, serverPub := mustKeypair(t)
	data := wireguard.ProtocolData{
		PrivateKey: serverPriv,
		PublicKey:  serverPub,
		Address:    []string{"10.8.0.1/30"},
	}
	clients := []domain.ClientConfig{
		testClient(t, "a"),
		testClient(t, "b"),
		testClient(t, "c"),
	}
	_, err := wireguard.RenderPeersForTest(data, clients)
	if err == nil || !strings.Contains(err.Error(), "no available address") {
		t.Fatalf("expected exhausted error, got %v", err)
	}
}

func TestClientPublicKeyError_Error(t *testing.T) {
	err := wireguard.ClientPublicKeyErrorForTest("alice")
	if err.Error() != `client "alice": public key (username) is required` {
		t.Fatalf("Error() = %q", err.Error())
	}
}
