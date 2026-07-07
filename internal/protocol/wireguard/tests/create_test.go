package wireguard_test

import (
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/protocol/testutil"
	"github.com/ivan-khludov/obscura/internal/protocol/wireguard"
)

func TestBuildProtocolData_GeneratesKeysAndDefaults(t *testing.T) {
	adapter := &wireguard.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		Protocol:        domain.ProtocolWireGuard,
		ProtocolOptions: wireguard.CreateOptions{},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-wg", protocol.BuildModeProvision)
	if err != nil {
		t.Fatal(err)
	}
	data, err := wireguard.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if data.PrivateKey == "" || data.PublicKey == "" {
		t.Fatalf("expected keypair, got private=%q public=%q", data.PrivateKey, data.PublicKey)
	}
	if len(data.Address) != 1 || data.Address[0] != wireguard.DefaultAddress {
		t.Fatalf("expected default address %q, got %v", wireguard.DefaultAddress, data.Address)
	}
}

func TestBuildProtocolData_allCreateOptions(t *testing.T) {
	adapter := &wireguard.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	_, psk := mustKeypair(t)
	spec := domain.CreateVPNSpec{
		Protocol: domain.ProtocolWireGuard,
		ProtocolOptions: wireguard.CreateOptions{
			System:                          true,
			Name:                            "wg0",
			MTU:                             1408,
			Address:                         []string{"10.9.0.1/24"},
			UDPTimeout:                      "5m",
			Workers:                         2,
			PeerPreSharedKey:                psk,
			PeerPersistentKeepaliveInterval: 30,
			PeerReserved:                    []int{1, 2, 3},
			ClientAllowedIPs:                []string{"192.168.0.0/16"},
			Detour:                          "direct",
			BindInterface:                   "eth0",
			Inet4BindAddress:                "192.0.2.1",
			Inet6BindAddress:                "2001:db8::1",
			BindAddressNoPort:               true,
			RoutingMark:                     "0x1",
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
		},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-wg", protocol.BuildModeProvision)
	if err != nil {
		t.Fatal(err)
	}
	data, err := wireguard.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !data.System || data.Name != "wg0" || data.Detour != "direct" {
		t.Fatalf("unexpected data: %#v", data)
	}
	if data.Address[0] != "10.9.0.1/24" {
		t.Fatalf("address = %v", data.Address)
	}
}

func TestBuildProtocolData_createOptionsFromSpec(t *testing.T) {
	adapter := &wireguard.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	opts := wireguard.CreateOptions{MTU: 1408, Address: []string{"10.8.0.1/24"}}
	for _, spec := range []domain.CreateVPNSpec{
		{ProtocolOptions: nil},
		{ProtocolOptions: wireguard.CreateOptions{}},
		{ProtocolOptions: opts},
		{ProtocolOptions: &opts},
		{ProtocolOptions: (*wireguard.CreateOptions)(nil)},
	} {
		if _, err := adapter.BuildProtocolData(ctx, spec, "tag", protocol.BuildModeProvision); err != nil {
			t.Fatalf("spec %#v: %v", spec.ProtocolOptions, err)
		}
	}
}

func TestBuildProtocolData_wrongOptionsType(t *testing.T) {
	adapter := &wireguard.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	_, err := adapter.BuildProtocolData(ctx, domain.CreateVPNSpec{ProtocolOptions: "bad"}, "tag", protocol.BuildModeProvision)
	if err == nil || !strings.Contains(err.Error(), "unexpected type") {
		t.Fatalf("expected type error, got %v", err)
	}
}

func TestBuildProtocolData_validationError(t *testing.T) {
	adapter := &wireguard.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		ProtocolOptions: wireguard.CreateOptions{MTU: 100},
	}
	_, err := adapter.BuildProtocolData(ctx, spec, "tag", protocol.BuildModeProvision)
	if err == nil || !strings.Contains(err.Error(), "mtu must be at least 1280") {
		t.Fatalf("expected mtu validation error, got %v", err)
	}
}

func TestBuildProtocolData_keyGenError(t *testing.T) {
	restore := wireguard.SetKeyGenFactoryForTest(func() *wireguard.KeyGen {
		return &wireguard.KeyGen{RandRead: errReader{}}
	})
	t.Cleanup(restore)
	adapter := &wireguard.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	_, err := adapter.BuildProtocolData(ctx, domain.CreateVPNSpec{ProtocolOptions: wireguard.CreateOptions{}}, "tag", protocol.BuildModeProvision)
	if err == nil || !strings.Contains(err.Error(), "generate wireguard server keypair") {
		t.Fatalf("expected keygen error, got %v", err)
	}
}

func TestNeedsInitialClient(t *testing.T) {
	if !(&wireguard.Adapter{}).NeedsInitialClient(domain.VPNConfig{}) {
		t.Fatal("expected true")
	}
}
