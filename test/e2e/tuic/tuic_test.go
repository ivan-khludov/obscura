//go:build e2e

package tuic_test

import (
	"os"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol/tuic"
	"github.com/ivan-khludov/obscura/test/e2e/runner"
)

const tlsServerName = "e2e-server"

var tuicUFWUDPPorts = []int{443, 4443, 4444, 4445, 4446, 4447, 4448}

var e2eEnv = runner.NewEnv(runner.Config{
	ProjectName: "obscura-e2e-tuic",
	UFWUDPPorts: tuicUFWUDPPorts,
})

func TestMain(m *testing.M) {
	os.Exit(runner.RunMain(runner.Config{
		ProjectName: "obscura-e2e-tuic",
		UFWUDPPorts: tuicUFWUDPPorts,
	}, m))
}

// TUICCase describes a declarative TUIC E2E scenario.
type TUICCase struct {
	ID      string
	VPNName string
	Port    int
	Extra   []string
	Check   func(t *testing.T, data tuic.ProtocolData, uri string, clientUUID string)
}

var tlsNameFlag = []string{"--tuic-tls-server-name", tlsServerName}

var cases = []TUICCase{
	{
		ID: "tc-basic", VPNName: "tc", Port: 443,
		Extra: append([]string{}, tlsNameFlag...),
		Check: func(t *testing.T, _ tuic.ProtocolData, uri, clientUUID string) {
			if !strings.Contains(uri, "congestion_control=cubic") {
				t.Fatalf("expected cubic in uri, got %q", uri)
			}
			if !strings.Contains(uri, clientUUID) {
				t.Fatalf("expected uuid %q in uri, got %q", clientUUID, uri)
			}
		},
	},
	{
		ID: "tc-bbr", VPNName: "tc-bbr", Port: 4443,
		Extra: append(append([]string{}, tlsNameFlag...), "--tuic-congestion-control", tuic.CongestionBBR),
		Check: func(t *testing.T, data tuic.ProtocolData, uri string, _ string) {
			if data.CongestionControl != tuic.CongestionBBR {
				t.Fatalf("congestion_control: got %q want %q", data.CongestionControl, tuic.CongestionBBR)
			}
			if !strings.Contains(uri, "congestion_control=bbr") {
				t.Fatalf("expected bbr in uri, got %q", uri)
			}
		},
	},
	{
		ID: "tc-new-reno", VPNName: "tc-nr", Port: 4444,
		Extra: append(append([]string{}, tlsNameFlag...), "--tuic-congestion-control", tuic.CongestionNewReno),
		Check: func(t *testing.T, data tuic.ProtocolData, uri string, _ string) {
			if data.CongestionControl != tuic.CongestionNewReno {
				t.Fatalf("congestion_control: got %q want %q", data.CongestionControl, tuic.CongestionNewReno)
			}
			if !strings.Contains(uri, "congestion_control=new_reno") {
				t.Fatalf("expected new_reno in uri, got %q", uri)
			}
		},
	},
	{
		ID: "tc-auth-timeout", VPNName: "tc-auth", Port: 4445,
		Extra: append(append([]string{}, tlsNameFlag...), "--tuic-auth-timeout", "3s"),
		Check: func(t *testing.T, data tuic.ProtocolData, _ string, _ string) {
			if data.AuthTimeout != "3s" {
				t.Fatalf("auth_timeout: got %q want 3s", data.AuthTimeout)
			}
		},
	},
	{
		ID: "tc-heartbeat", VPNName: "tc-hb", Port: 4446,
		Extra: append(append([]string{}, tlsNameFlag...), "--tuic-heartbeat", "10s"),
		Check: func(t *testing.T, data tuic.ProtocolData, _ string, _ string) {
			if data.Heartbeat != "10s" {
				t.Fatalf("heartbeat: got %q want 10s", data.Heartbeat)
			}
		},
	},
	{
		ID: "tc-zero-rtt", VPNName: "tc-zrtt", Port: 4447,
		Extra: append(append([]string{}, tlsNameFlag...), "--tuic-zero-rtt-handshake"),
		Check: func(t *testing.T, data tuic.ProtocolData, _ string, _ string) {
			if !data.ZeroRTTHandshake {
				t.Fatal("expected zero_rtt_handshake in protocol data")
			}
		},
	},
	{
		ID: "tc-quic-tuning", VPNName: "tc-quic", Port: 4448,
		Extra: append(append([]string{}, tlsNameFlag...),
			"--tuic-initial-packet-size", "1200",
			"--tuic-disable-path-mtu-discovery",
			"--tuic-http2-idle-timeout", "30s",
			"--tuic-http2-max-concurrent-streams", "100"),
		Check: func(t *testing.T, data tuic.ProtocolData, _ string, _ string) {
			if data.InitialPacketSize != 1200 {
				t.Fatalf("initial_packet_size: got %d want 1200", data.InitialPacketSize)
			}
			if !data.DisablePathMTUDiscovery {
				t.Fatal("expected disable_path_mtu_discovery")
			}
			if data.HTTP2 == nil {
				t.Fatal("expected http2 options in protocol data")
			}
			if data.HTTP2.IdleTimeout != "30s" {
				t.Fatalf("http2 idle_timeout: got %q want 30s", data.HTTP2.IdleTimeout)
			}
			if data.HTTP2.MaxConcurrentStreams != 100 {
				t.Fatalf("http2 max_concurrent_streams: got %d want 100", data.HTTP2.MaxConcurrentStreams)
			}
		},
	},
}

func TestTUICConnect(t *testing.T) {
	r := runner.NewRunner(t, e2eEnv)

	for _, tc := range cases {
		t.Run(tc.ID, func(t *testing.T) {
			result, err := r.CreateVPNFull(tc.VPNName, "tuic", tc.Port, tc.Extra...)
			if err != nil {
				t.Fatalf("create vpn: %v", err)
			}
			t.Cleanup(func() {
				if err := r.DeleteVPN(tc.VPNName); err != nil {
					t.Errorf("delete vpn %q: %v", tc.VPNName, err)
				}
			})

			if !strings.HasPrefix(result.URI, "tuic://") {
				t.Fatalf("expected tuic URI, got %q", result.URI)
			}
			if result.Client.Username == "" {
				t.Fatal("expected client uuid in create result")
			}

			data, err := tuic.ParseProtocolData(result.VPN.ProtocolData)
			if err != nil {
				t.Fatalf("parse protocol data: %v", err)
			}
			if tc.Check != nil {
				tc.Check(t, data, result.URI, result.Client.Username)
			}

			cfg, err := runner.TUICConnectConfigFromCreate(result)
			if err != nil {
				t.Fatalf("connect config: %v", err)
			}

			if err := r.CurlViaTUIC(cfg); err != nil {
				t.Fatalf("curl via tuic: %v", err)
			}
		})
	}
}
