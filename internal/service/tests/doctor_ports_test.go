package service_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/trojan"
	"github.com/ivan-khludov/obscura/internal/protocol/vmess"
	"github.com/ivan-khludov/obscura/internal/service"
)

func TestListenProtosForVPN(t *testing.T) {
	t.Parallel()
	cases := []struct {
		protocol string
		raw      []byte
		want     []string
	}{
		{protocol: "socks5", want: []string{"tcp"}},
		{protocol: "hysteria2", want: []string{"udp"}},
		{protocol: "tuic", want: []string{"udp"}},
		{protocol: "wireguard", want: []string{"udp"}},
	}
	for _, tc := range cases {
		got := service.ListenProtosForVPNForTest(domain.VPN{Protocol: tc.protocol, ProtocolData: tc.raw})
		if len(got) != len(tc.want) || got[0] != tc.want[0] {
			t.Fatalf("%s: got %v want %v", tc.protocol, got, tc.want)
		}
	}

	trojanQUIC, err := trojan.MarshalProtocolData(trojan.ProtocolData{TransportType: "quic"})
	if err != nil {
		t.Fatal(err)
	}
	if got := service.ListenProtosForVPNForTest(domain.VPN{Protocol: "trojan", ProtocolData: trojanQUIC}); got[0] != "udp" {
		t.Fatalf("trojan quic: got %v", got)
	}
	trojanTCP, err := trojan.MarshalProtocolData(trojan.ProtocolData{
		TransportType: "ws",
		TransportWS:   &trojan.TransportWS{Path: "/"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := service.ListenProtosForVPNForTest(domain.VPN{Protocol: "trojan", ProtocolData: trojanTCP}); got[0] != "tcp" {
		t.Fatalf("trojan ws: got %v", got)
	}

	vmessQUIC, err := vmess.MarshalProtocolData(vmess.ProtocolData{TransportType: "quic"})
	if err != nil {
		t.Fatal(err)
	}
	if got := service.ListenProtosForVPNForTest(domain.VPN{Protocol: "vmess", ProtocolData: vmessQUIC}); got[0] != "udp" {
		t.Fatalf("vmess quic: got %v", got)
	}
}

func TestTrojanTransportIsQUICInvalid(t *testing.T) {
	if service.TrojanTransportIsQUICForTest([]byte("bad")) {
		t.Fatal("expected false for invalid data")
	}
}

func TestVmessTransportIsQUICInvalid(t *testing.T) {
	if service.VmessTransportIsQUICForTest([]byte("bad")) {
		t.Fatal("expected false for invalid data")
	}
}

func TestBuildListenChecks(t *testing.T) {
	svc, st := newTestService(t)
	ctx := context.Background()
	vpn := &domain.VPN{
		Name: "main", Protocol: "socks5", Tag: "vpn-main", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080},
	}
	if err := st.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	client := &domain.Client{VPNID: vpn.ID, Name: "default", Username: "u", Password: "p", Enabled: true}
	if err := st.CreateClient(ctx, client); err != nil {
		t.Fatal(err)
	}
	checks := svc.BuildListenChecksForTest(ctx)
	if len(checks) != 1 || checks[0].VPNName != "main" || checks[0].Port != 1080 {
		t.Fatalf("unexpected checks: %#v", checks)
	}
}

func TestBuildListenChecksSkipsNoEnabledClients(t *testing.T) {
	svc, st := newTestService(t)
	ctx := context.Background()
	vpn := &domain.VPN{
		Name: "empty", Protocol: "socks5", Tag: "vpn-empty", Enabled: true,
		Listen: domain.ListenOptions{ListenPort: 1081},
	}
	if err := st.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	client := &domain.Client{VPNID: vpn.ID, Name: "off", Username: "u", Password: "p", Enabled: false}
	if err := st.CreateClient(ctx, client); err != nil {
		t.Fatal(err)
	}
	if checks := svc.BuildListenChecksForTest(ctx); len(checks) != 0 {
		t.Fatalf("expected no checks, got %#v", checks)
	}
}

func TestBuildListenChecksClosedStore(t *testing.T) {
	svc := closedStoreService(t)
	if checks := svc.BuildListenChecksForTest(context.Background()); checks != nil {
		t.Fatalf("expected nil, got %#v", checks)
	}
}

func TestBuildListenChecksSort(t *testing.T) {
	svc, st := newTestService(t)
	ctx := context.Background()
	for _, spec := range []struct {
		name string
		port int
	}{
		{"beta", 12002},
		{"alpha", 12001},
	} {
		vpn := &domain.VPN{
			Name: spec.name, Protocol: "socks5", Tag: "vpn-" + spec.name, Enabled: true,
			Listen: domain.ListenOptions{ListenPort: spec.port},
		}
		if err := st.CreateVPN(ctx, vpn); err != nil {
			t.Fatal(err)
		}
		if err := st.CreateClient(ctx, &domain.Client{VPNID: vpn.ID, Name: "c", Username: "u", Password: "p", Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	checks := svc.BuildListenChecksForTest(ctx)
	if len(checks) != 2 || checks[0].VPNName != "alpha" {
		t.Fatalf("checks=%#v", checks)
	}
}

func TestListenProtosDefaultTCP(t *testing.T) {
	got := service.ListenProtosForVPNForTest(domain.VPN{Protocol: "socks5"})
	if got[0] != "tcp" {
		t.Fatalf("got %v", got)
	}
}

func TestBuildListenChecksSamePortSort(t *testing.T) {
	svc, st := newTestService(t)
	ctx := context.Background()
	port := 1083
	for _, name := range []string{"beta", "alpha"} {
		vpn := &domain.VPN{Name: name, Protocol: "socks5", Tag: "vpn-" + name, Enabled: true, Listen: domain.ListenOptions{ListenPort: port}}
		if err := st.CreateVPN(ctx, vpn); err != nil {
			t.Fatal(err)
		}
		if err := st.CreateClient(ctx, &domain.Client{VPNID: vpn.ID, Name: "c", Username: "u", Password: "p", Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	checks := svc.BuildListenChecksForTest(ctx)
	if len(checks) != 2 || checks[0].VPNName != "alpha" {
		t.Fatalf("checks=%#v", checks)
	}
}

func TestBuildListenChecksListClientsError(t *testing.T) {
	svc, st := newTestService(t)
	ctx := context.Background()
	vpn := &domain.VPN{Name: "main", Protocol: "socks5", Tag: "vpn-main", Enabled: true, Listen: domain.ListenOptions{ListenPort: 1082}}
	if err := st.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	fs := wrapFaultStore(st)
	fs.listClientsErr = fmt.Errorf("list failed")
	svc.SetStoreForTest(fs)
	if checks := svc.BuildListenChecksForTest(ctx); len(checks) != 0 {
		t.Fatalf("expected empty checks, got %#v", checks)
	}
}

func TestListenProtosVmessTCP(t *testing.T) {
	tcp, err := vmess.MarshalProtocolData(vmess.ProtocolData{TransportType: "ws", TransportWS: &vmess.TransportWS{Path: "/"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := service.ListenProtosForVPNForTest(domain.VPN{Protocol: "vmess", ProtocolData: tcp}); got[0] != "tcp" {
		t.Fatalf("got %v", got)
	}
}
