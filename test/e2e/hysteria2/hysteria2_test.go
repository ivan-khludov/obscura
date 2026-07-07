//go:build e2e

package hysteria2_test

import (
	"os"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol/hysteria2"
	"github.com/ivan-khludov/obscura/test/e2e/runner"
)

const (
	tlsServerName = "e2e-server"
	obfsPassword  = "e2eobfs123"
)

var hy2UFWUDPPorts = []int{443, 4443, 4444, 4445, 4446, 4447, 4448, 4449, 4450}

var e2eEnv = runner.NewEnv(runner.Config{
	ProjectName: "obscura-e2e-hysteria2",
	UFWUDPPorts: hy2UFWUDPPorts,
})

func TestMain(m *testing.M) {
	os.Exit(runner.RunMain(runner.Config{
		ProjectName: "obscura-e2e-hysteria2",
		UFWUDPPorts: hy2UFWUDPPorts,
	}, m))
}

// Hysteria2Case describes a declarative Hysteria2 E2E scenario.
type Hysteria2Case struct {
	ID      string
	VPNName string
	Port    int
	Extra   []string
	Check   func(t *testing.T, data hysteria2.ProtocolData, uri string)
}

var tlsNameFlag = []string{"--hy2-tls-server-name", tlsServerName}

var brutalFlags = []string{"--hy2-up-mbps", "100", "--hy2-down-mbps", "100"}
var obfsFlags = []string{"--hy2-obfs-password", obfsPassword}

var cases = []Hysteria2Case{
	{
		ID: "hy-basic", VPNName: "hy", Port: 443,
		Extra: append([]string{}, tlsNameFlag...),
	},
	{
		ID: "hy-brutal", VPNName: "hy-brutal", Port: 4443,
		Extra: append(append([]string{}, tlsNameFlag...), brutalFlags...),
		Check: func(t *testing.T, data hysteria2.ProtocolData, _ string) {
			if data.UpMbps != 100 || data.DownMbps != 100 {
				t.Fatalf("brutal mbps: got %d/%d want 100/100", data.UpMbps, data.DownMbps)
			}
		},
	},
	{
		ID: "hy-obfs", VPNName: "hy-obfs", Port: 4444,
		Extra: append(append([]string{}, tlsNameFlag...), obfsFlags...),
		Check: func(t *testing.T, data hysteria2.ProtocolData, uri string) {
			if data.ObfsPassword == "" {
				t.Fatal("expected obfs password in protocol data")
			}
			if !strings.Contains(uri, "obfs=salamander") {
				t.Fatalf("expected obfs in uri, got %q", uri)
			}
		},
	},
	{
		ID: "hy-brutal-obfs", VPNName: "hy-bo", Port: 4445,
		Extra: append(append(append([]string{}, tlsNameFlag...), brutalFlags...), obfsFlags...),
		Check: func(t *testing.T, data hysteria2.ProtocolData, uri string) {
			if data.UpMbps != 100 || data.DownMbps != 100 {
				t.Fatalf("brutal mbps: got %d/%d want 100/100", data.UpMbps, data.DownMbps)
			}
			if data.ObfsPassword == "" {
				t.Fatal("expected obfs password in protocol data")
			}
			if !strings.Contains(uri, "obfs=salamander") {
				t.Fatalf("expected obfs in uri, got %q", uri)
			}
		},
	},
	{
		ID: "hy-masquerade-url", VPNName: "hy-mq", Port: 4446,
		Extra: append(append([]string{}, tlsNameFlag...), "--hy2-masquerade", "http://target/"),
		Check: func(t *testing.T, data hysteria2.ProtocolData, _ string) {
			if data.MasqueradeURL != "http://target/" {
				t.Fatalf("masquerade url: got %q want http://target/", data.MasqueradeURL)
			}
		},
	},
	{
		ID: "hy-masquerade-proxy", VPNName: "hy-mp", Port: 4447,
		Extra: append(append([]string{}, tlsNameFlag...),
			"--hy2-masquerade-type", "proxy",
			"--hy2-masquerade-url", "http://target/",
			"--hy2-masquerade-rewrite-host"),
		Check: func(t *testing.T, data hysteria2.ProtocolData, _ string) {
			if data.Masquerade == nil {
				t.Fatal("expected masquerade object in protocol data")
			}
			if data.Masquerade.Type != hysteria2.MasqueradeTypeProxy {
				t.Fatalf("masquerade type: got %q want proxy", data.Masquerade.Type)
			}
			if data.Masquerade.URL != "http://target/" {
				t.Fatalf("masquerade url: got %q want http://target/", data.Masquerade.URL)
			}
			if !data.Masquerade.RewriteHost {
				t.Fatal("expected masquerade rewrite_host")
			}
		},
	},
	{
		ID: "hy-masquerade-string", VPNName: "hy-ms", Port: 4448,
		Extra: append(append([]string{}, tlsNameFlag...),
			"--hy2-masquerade-type", "string",
			"--hy2-masquerade-status-code", "404",
			"--hy2-masquerade-content", "notfound"),
		Check: func(t *testing.T, data hysteria2.ProtocolData, _ string) {
			if data.Masquerade == nil {
				t.Fatal("expected masquerade object in protocol data")
			}
			if data.Masquerade.Type != hysteria2.MasqueradeTypeString {
				t.Fatalf("masquerade type: got %q want string", data.Masquerade.Type)
			}
			if data.Masquerade.StatusCode != 404 {
				t.Fatalf("masquerade status: got %d want 404", data.Masquerade.StatusCode)
			}
			if data.Masquerade.Content != "notfound" {
				t.Fatalf("masquerade content: got %q want notfound", data.Masquerade.Content)
			}
		},
	},
	{
		ID: "hy-bbr", VPNName: "hy-bbr", Port: 4449,
		Extra: append(append([]string{}, tlsNameFlag...),
			"--hy2-ignore-client-bandwidth", "--hy2-bbr-profile", hysteria2.BBRProfileStandard),
		Check: func(t *testing.T, data hysteria2.ProtocolData, _ string) {
			if !data.IgnoreClientBandwidth {
				t.Fatal("expected ignore_client_bandwidth in protocol data")
			}
			if data.BBRProfile != hysteria2.BBRProfileStandard {
				t.Fatalf("bbr profile: got %q want %q", data.BBRProfile, hysteria2.BBRProfileStandard)
			}
		},
	},
	{
		ID: "hy-quic-tuning", VPNName: "hy-quic", Port: 4450,
		Extra: append(append([]string{}, tlsNameFlag...),
			"--hy2-initial-packet-size", "1200",
			"--hy2-disable-path-mtu-discovery",
			"--hy2-http2-idle-timeout", "30s",
			"--hy2-http2-max-concurrent-streams", "100"),
		Check: func(t *testing.T, data hysteria2.ProtocolData, _ string) {
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

func TestHysteria2Connect(t *testing.T) {
	r := runner.NewRunner(t, e2eEnv)

	for _, tc := range cases {
		t.Run(tc.ID, func(t *testing.T) {
			result, err := r.CreateVPNFull(tc.VPNName, "hysteria2", tc.Port, tc.Extra...)
			if err != nil {
				t.Fatalf("create vpn: %v", err)
			}
			t.Cleanup(func() {
				if err := r.DeleteVPN(tc.VPNName); err != nil {
					t.Errorf("delete vpn %q: %v", tc.VPNName, err)
				}
			})

			if !strings.HasPrefix(result.URI, "hysteria2://") {
				t.Fatalf("expected hysteria2 URI, got %q", result.URI)
			}

			data, err := hysteria2.ParseProtocolData(result.VPN.ProtocolData)
			if err != nil {
				t.Fatalf("parse protocol data: %v", err)
			}
			if tc.Check != nil {
				tc.Check(t, data, result.URI)
			}

			cfg, err := runner.Hysteria2ConnectConfigFromCreate(result)
			if err != nil {
				t.Fatalf("connect config: %v", err)
			}

			if err := r.CurlViaHysteria2(cfg); err != nil {
				t.Fatalf("curl via hysteria2: %v", err)
			}
		})
	}
}
