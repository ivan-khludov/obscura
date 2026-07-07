//go:build e2e

package wireguard_test

import (
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol/wireguard"
	"github.com/ivan-khludov/obscura/test/e2e/runner"
)

const testPSK = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

var wgUFWUDPPorts = []int{
	51820, 51821, 51822, 51823, 51824, 51825,
	51826, 51827, 51828, 51829, 51830, 51831,
}

var e2eEnv = runner.NewEnv(runner.Config{
	ProjectName: "obscura-e2e-wireguard",
	UFWUDPPorts: wgUFWUDPPorts,
})

func TestMain(m *testing.M) {
	os.Exit(runner.RunMain(runner.Config{
		ProjectName: "obscura-e2e-wireguard",
		UFWUDPPorts: wgUFWUDPPorts,
	}, m))
}

// WGCase describes a declarative WireGuard E2E scenario.
type WGCase struct {
	ID      string
	VPNName string
	Port    int
	Extra   []string
	Check   func(t *testing.T, result runner.VPNCreateResult, uri *url.URL)
}

var cases = []WGCase{
	{ID: "wg-basic", VPNName: "wg", Port: 51820},
	{
		ID: "wg-mtu", VPNName: "wg-mtu", Port: 51821,
		Extra: []string{"--wg-mtu", "1420"},
		Check: func(t *testing.T, result runner.VPNCreateResult, _ *url.URL) {
			data, err := wireguard.ParseProtocolData(result.VPN.ProtocolData)
			if err != nil {
				t.Fatalf("parse protocol data: %v", err)
			}
			if data.MTU != 1420 {
				t.Fatalf("mtu: got %d want 1420", data.MTU)
			}
		},
	},
	{
		ID: "wg-subnet", VPNName: "wg-sub", Port: 51822,
		Extra: []string{"--wg-address", "10.9.0.1/24"},
		Check: func(t *testing.T, result runner.VPNCreateResult, _ *url.URL) {
			cfg, err := runner.WGConnectConfigFromCreate(result)
			if err != nil {
				t.Fatalf("connect config: %v", err)
			}
			if cfg.ClientAddress != "10.9.0.2/32" {
				t.Fatalf("client address: got %q want 10.9.0.2/32", cfg.ClientAddress)
			}
		},
	},
	{
		ID: "wg-system", VPNName: "wg-sys", Port: 51823,
		Extra: []string{"--wg-system"},
		Check: func(t *testing.T, result runner.VPNCreateResult, _ *url.URL) {
			data, err := wireguard.ParseProtocolData(result.VPN.ProtocolData)
			if err != nil {
				t.Fatalf("parse protocol data: %v", err)
			}
			if !data.System {
				t.Fatal("expected system wireguard on server")
			}
		},
	},
	{
		ID: "wg-psk", VPNName: "wg-psk", Port: 51824,
		Extra: []string{"--wg-peer-psk", testPSK},
		Check: func(t *testing.T, result runner.VPNCreateResult, uri *url.URL) {
			data, err := wireguard.ParseProtocolData(result.VPN.ProtocolData)
			if err != nil {
				t.Fatalf("parse protocol data: %v", err)
			}
			if data.PeerPreSharedKey != testPSK {
				t.Fatalf("psk: got %q want %q", data.PeerPreSharedKey, testPSK)
			}
			if uri.Query().Get("presharedkey") != testPSK {
				t.Fatalf("uri presharedkey: got %q want %q", uri.Query().Get("presharedkey"), testPSK)
			}
		},
	},
	{
		ID: "wg-keepalive", VPNName: "wg-ka", Port: 51825,
		Extra: []string{"--wg-peer-keepalive", "15"},
		Check: func(t *testing.T, result runner.VPNCreateResult, uri *url.URL) {
			if uri.Query().Get("keepalive") != "15" {
				t.Fatalf("keepalive: got %q want 15", uri.Query().Get("keepalive"))
			}
			cfg, err := runner.WGConnectConfigFromCreate(result)
			if err != nil {
				t.Fatalf("connect config: %v", err)
			}
			if cfg.Keepalive != 15 {
				t.Fatalf("keepalive config: got %d want 15", cfg.Keepalive)
			}
		},
	},
	{
		ID: "wg-reserved", VPNName: "wg-res", Port: 51826,
		Extra: []string{"--wg-peer-reserved", "1,2,3"},
		Check: func(t *testing.T, result runner.VPNCreateResult, _ *url.URL) {
			cfg, err := runner.WGConnectConfigFromCreate(result)
			if err != nil {
				t.Fatalf("connect config: %v", err)
			}
			if len(cfg.Reserved) != 3 || cfg.Reserved[0] != 1 || cfg.Reserved[1] != 2 || cfg.Reserved[2] != 3 {
				t.Fatalf("reserved: got %v want [1 2 3]", cfg.Reserved)
			}
		},
	},
	{
		ID: "wg-client-allowed-ips", VPNName: "wg-aip", Port: 51827,
		Extra: []string{"--wg-client-allowed-ips", "10.8.0.0/24", "--wg-client-allowed-ips", "192.168.0.0/16"},
		Check: func(t *testing.T, _ runner.VPNCreateResult, uri *url.URL) {
			got := uri.Query().Get("allowedips")
			want := "10.8.0.0/24,192.168.0.0/16"
			if got != want {
				t.Fatalf("allowedips: got %q want %q", got, want)
			}
		},
	},
	{
		ID: "wg-name", VPNName: "wg-name", Port: 51828,
		Extra: []string{"--wg-name", "wg-e2e"},
		Check: func(t *testing.T, result runner.VPNCreateResult, _ *url.URL) {
			data, err := wireguard.ParseProtocolData(result.VPN.ProtocolData)
			if err != nil {
				t.Fatalf("parse protocol data: %v", err)
			}
			if data.Name != "wg-e2e" {
				t.Fatalf("name: got %q want wg-e2e", data.Name)
			}
		},
	},
	{
		ID: "wg-workers", VPNName: "wg-wrk", Port: 51829,
		Extra: []string{"--wg-workers", "2"},
		Check: func(t *testing.T, result runner.VPNCreateResult, _ *url.URL) {
			data, err := wireguard.ParseProtocolData(result.VPN.ProtocolData)
			if err != nil {
				t.Fatalf("parse protocol data: %v", err)
			}
			if data.Workers != 2 {
				t.Fatalf("workers: got %d want 2", data.Workers)
			}
		},
	},
	{
		ID: "wg-udp-timeout", VPNName: "wg-ut", Port: 51830,
		Extra: []string{"--wg-udp-timeout", "3m"},
		Check: func(t *testing.T, result runner.VPNCreateResult, _ *url.URL) {
			data, err := wireguard.ParseProtocolData(result.VPN.ProtocolData)
			if err != nil {
				t.Fatalf("parse protocol data: %v", err)
			}
			if data.UDPTimeout != "3m" {
				t.Fatalf("udp_timeout: got %q want 3m", data.UDPTimeout)
			}
		},
	},
	{
		ID: "wg-dial-safe", VPNName: "wg-dial", Port: 51831,
		Extra: []string{"--wg-reuse-addr", "--wg-connect-timeout", "5s", "--wg-udp-fragment"},
		Check: func(t *testing.T, result runner.VPNCreateResult, _ *url.URL) {
			data, err := wireguard.ParseProtocolData(result.VPN.ProtocolData)
			if err != nil {
				t.Fatalf("parse protocol data: %v", err)
			}
			if !data.ReuseAddr {
				t.Fatal("expected reuse_addr")
			}
			if data.ConnectTimeout != "5s" {
				t.Fatalf("connect_timeout: got %q want 5s", data.ConnectTimeout)
			}
			if !data.UDPFragment {
				t.Fatal("expected udp_fragment")
			}
		},
	},
}

func TestWireguardConnect(t *testing.T) {
	r := runner.NewRunner(t, e2eEnv)

	for _, tc := range cases {
		t.Run(tc.ID, func(t *testing.T) {
			result, err := r.CreateVPNFull(tc.VPNName, "wireguard", tc.Port, tc.Extra...)
			if err != nil {
				t.Fatalf("create vpn: %v", err)
			}
			t.Cleanup(func() {
				if err := r.DeleteVPN(tc.VPNName); err != nil {
					t.Errorf("delete vpn %q: %v", tc.VPNName, err)
				}
			})

			if !strings.HasPrefix(result.URI, "wireguard://") {
				t.Fatalf("expected wireguard URI, got %q", result.URI)
			}
			parsed, err := url.Parse(result.URI)
			if err != nil {
				t.Fatalf("parse uri: %v", err)
			}
			if parsed.Hostname() != runner.ServerHost {
				t.Fatalf("expected client host %q in uri, got %q", runner.ServerHost, parsed.Hostname())
			}

			if tc.Check != nil {
				tc.Check(t, result, parsed)
			}

			targetIP, err := r.ResolveHostIP("target")
			if err != nil {
				t.Fatalf("resolve target: %v", err)
			}

			cfg, err := runner.WGConnectConfigFromCreate(result)
			if err != nil {
				t.Fatalf("connect config: %v", err)
			}
			cfg.RouteCIDRs = []string{targetIP + "/32"}

			if err := r.CurlViaWireguard(cfg); err != nil {
				t.Fatalf("curl via wireguard: %v", err)
			}
		})
	}
}
