//go:build e2e

package vless_test

import (
	"os"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol/vless"
	"github.com/ivan-khludov/obscura/test/e2e/runner"
)

const tlsServerName = "e2e-server"

var vlessUFWPorts = []int{443, 444, 4443, 4444, 4451, 4452, 8443, 8444, 8445, 8446, 8447}

var e2eEnv = runner.NewEnv(runner.Config{
	ProjectName: "obscura-e2e-vless",
	UFWPorts:    vlessUFWPorts,
	UFWUDPPorts: []int{8447},
})

func TestMain(m *testing.M) {
	os.Exit(runner.RunMain(runner.Config{
		ProjectName: "obscura-e2e-vless",
		UFWPorts:    vlessUFWPorts,
		UFWUDPPorts: []int{8447},
	}, m))
}

// VLESSCase describes a declarative VLESS E2E scenario.
type VLESSCase struct {
	ID                      string
	VPNName                 string
	Port                    int
	Extra                   []string
	Multiplex               bool
	MultiplexPadding        bool
	MultiplexBrutal         bool
	MultiplexBrutalUpMbps   int
	MultiplexBrutalDownMbps int
	Reality                 bool
	WantFlow                string
	SkipConnect             bool
}

var tlsNameFlag = []string{"--tls-server-name", tlsServerName}

var cases = []VLESSCase{
	{
		ID: "vl-basic", VPNName: "vl", Port: 443,
		Extra: append([]string{}, tlsNameFlag...),
	},
	{
		ID: "vl-multiplex", VPNName: "vl-mux", Port: 4443,
		Extra:     append(append([]string{}, tlsNameFlag...), "--multiplex"),
		Multiplex: true,
	},
	{
		ID: "vl-multiplex-padding", VPNName: "vl-mux-pad", Port: 4444,
		Extra:     append(append([]string{}, tlsNameFlag...), "--multiplex", "--multiplex-padding"),
		Multiplex: true, MultiplexPadding: true,
	},
	{
		ID: "vl-ws", VPNName: "vl-ws", Port: 8443,
		Extra: append(append([]string{}, tlsNameFlag...), "--transport", "ws", "--transport-path", "/video"),
	},
	{
		ID: "vl-grpc", VPNName: "vl-grpc", Port: 8444,
		Extra: append(append([]string{}, tlsNameFlag...), "--transport", "grpc", "--transport-service-name", "TunService"),
	},
	{
		ID: "vl-http", VPNName: "vl-http", Port: 8445,
		Extra: append(append([]string{}, tlsNameFlag...), "--transport", "http", "--transport-path", "/api"),
	},
	{
		ID: "vl-httpupgrade", VPNName: "vl-hu", Port: 8446,
		Extra: append(append([]string{}, tlsNameFlag...), "--transport", "httpupgrade", "--transport-path", "/up"),
	},
	{
		ID: "vl-quic", VPNName: "vl-quic", Port: 8447,
		Extra: append(append([]string{}, tlsNameFlag...), "--transport", "quic"),
	},
	{
		ID: "vl-reality", VPNName: "vl-st", Port: 444,
		Extra:   []string{"--reality", "--reality-handshake", "www.bing.com"},
		Reality: true,
	},
	{
		ID: "vl-vision", VPNName: "vl-vis", Port: 4451,
		Extra:    append(append([]string{}, tlsNameFlag...), "--vless-flow", vless.FlowVision),
		WantFlow: vless.FlowVision,
	},
	{
		ID: "vl-multiplex-brutal", VPNName: "vl-brutal", Port: 4452,
		Extra: append(append([]string{}, tlsNameFlag...),
			"--multiplex", "--multiplex-brutal",
			"--multiplex-brutal-up-mbps", "100", "--multiplex-brutal-down-mbps", "100"),
		Multiplex: true, MultiplexBrutal: true,
		MultiplexBrutalUpMbps: 100, MultiplexBrutalDownMbps: 100,
		SkipConnect: true,
	},
}

func TestVLESSConnect(t *testing.T) {
	r := runner.NewRunner(t, e2eEnv)

	for _, tc := range cases {
		t.Run(tc.ID, func(t *testing.T) {
			result, err := r.CreateVPNFull(tc.VPNName, "vless", tc.Port, tc.Extra...)
			if err != nil {
				t.Fatalf("create vpn: %v", err)
			}
			t.Cleanup(func() {
				if err := r.DeleteVPN(tc.VPNName); err != nil {
					t.Errorf("delete vpn %q: %v", tc.VPNName, err)
				}
			})

			if !strings.HasPrefix(result.URI, "vless://") {
				t.Fatalf("expected vless URI, got %q", result.URI)
			}

			data, err := vless.ParseProtocolData(result.VPN.ProtocolData)
			if err != nil {
				t.Fatalf("parse protocol data: %v", err)
			}
			if data.RealityEnabled != tc.Reality {
				t.Fatalf("reality flag: got %v want %v", data.RealityEnabled, tc.Reality)
			}
			if tc.Reality && data.RealityPublicKey == "" {
				t.Fatal("expected reality public key in protocol data")
			}
			if tc.WantFlow != "" && data.DefaultFlow != tc.WantFlow {
				t.Fatalf("default flow: got %q want %q", data.DefaultFlow, tc.WantFlow)
			}
			if tc.MultiplexBrutal {
				if !data.MultiplexBrutal {
					t.Fatal("expected multiplex brutal in protocol data")
				}
				if data.MultiplexBrutalUpMbps != tc.MultiplexBrutalUpMbps || data.MultiplexBrutalDownMbps != tc.MultiplexBrutalDownMbps {
					t.Fatalf("brutal mbps: got %d/%d want %d/%d",
						data.MultiplexBrutalUpMbps, data.MultiplexBrutalDownMbps,
						tc.MultiplexBrutalUpMbps, tc.MultiplexBrutalDownMbps)
				}
			}

			cfg, err := runner.VLESSConnectConfigFromCreate(
				result, tc.Multiplex, tc.MultiplexPadding, tc.MultiplexBrutal,
				tc.MultiplexBrutalUpMbps, tc.MultiplexBrutalDownMbps,
			)
			if err != nil {
				t.Fatalf("connect config: %v", err)
			}
			if tc.WantFlow != "" && cfg.Flow != tc.WantFlow {
				t.Fatalf("flow: got %q want %q", cfg.Flow, tc.WantFlow)
			}

			if tc.SkipConnect {
				if err := r.CheckVlessClientConfig(cfg); err != nil {
					t.Fatalf("check vless client config: %v", err)
				}
				return
			}

			if err := r.CurlViaVless(cfg); err != nil {
				t.Fatalf("curl via vless: %v", err)
			}
		})
	}
}
