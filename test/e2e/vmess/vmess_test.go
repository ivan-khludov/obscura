//go:build e2e

package vmess_test

import (
	"os"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol/vmess"
	"github.com/ivan-khludov/obscura/test/e2e/runner"
)

const tlsServerName = "e2e-server"

var vmessUFWPorts = []int{443, 444, 4443, 4444, 8080, 4451, 4452, 8443, 8444, 8445, 8446, 8447}

var e2eEnv = runner.NewEnv(runner.Config{
	ProjectName: "obscura-e2e-vmess",
	UFWPorts:    vmessUFWPorts,
	UFWUDPPorts: []int{8447},
})

func TestMain(m *testing.M) {
	os.Exit(runner.RunMain(runner.Config{
		ProjectName: "obscura-e2e-vmess",
		UFWPorts:    vmessUFWPorts,
		UFWUDPPorts: []int{8447},
	}, m))
}

// VMessCase describes a declarative VMess E2E scenario.
type VMessCase struct {
	ID                      string
	VPNName                 string
	Port                    int
	Extra                   []string
	Multiplex               bool
	MultiplexPadding        bool
	MultiplexBrutal         bool
	MultiplexBrutalUpMbps   int
	MultiplexBrutalDownMbps int
	NoTLS                   bool
	Reality                 bool
	WantAlterID             int
	SkipConnect             bool // brutal needs tcp-brutal kernel module for live traffic
}

var tlsNameFlag = []string{"--tls-server-name", tlsServerName}

var cases = []VMessCase{
	{
		ID: "vm-basic", VPNName: "vm", Port: 443,
		Extra: append([]string{}, tlsNameFlag...),
	},
	{
		ID: "vm-multiplex", VPNName: "vm-mux", Port: 4443,
		Extra:     append(append([]string{}, tlsNameFlag...), "--multiplex"),
		Multiplex: true,
	},
	{
		ID: "vm-multiplex-padding", VPNName: "vm-mux-pad", Port: 4444,
		Extra:     append(append([]string{}, tlsNameFlag...), "--multiplex", "--multiplex-padding"),
		Multiplex: true, MultiplexPadding: true,
	},
	{
		ID: "vm-ws", VPNName: "vm-ws", Port: 8443,
		Extra: append(append([]string{}, tlsNameFlag...), "--transport", "ws", "--transport-path", "/video"),
	},
	{
		ID: "vm-grpc", VPNName: "vm-grpc", Port: 8444,
		Extra: append(append([]string{}, tlsNameFlag...), "--transport", "grpc", "--transport-service-name", "TunService"),
	},
	{
		ID: "vm-http", VPNName: "vm-http", Port: 8445,
		Extra: append(append([]string{}, tlsNameFlag...), "--transport", "http", "--transport-path", "/api"),
	},
	{
		ID: "vm-httpupgrade", VPNName: "vm-hu", Port: 8446,
		Extra: append(append([]string{}, tlsNameFlag...), "--transport", "httpupgrade", "--transport-path", "/up"),
	},
	{
		ID: "vm-quic", VPNName: "vm-quic", Port: 8447,
		Extra: append(append([]string{}, tlsNameFlag...), "--transport", "quic"),
	},
	{
		ID: "vm-reality", VPNName: "vm-st", Port: 444,
		Extra:   []string{"--reality", "--reality-handshake", "www.bing.com"},
		Reality: true,
	},
	{
		ID: "vm-no-tls", VPNName: "vm-plain", Port: 8080,
		Extra: []string{"--vmess-no-tls"},
		NoTLS: true,
	},
	{
		ID: "vm-alter-id", VPNName: "vm-aid", Port: 4451,
		Extra:       append(append([]string{}, tlsNameFlag...), "--vmess-alter-id", "64"),
		WantAlterID: 64,
	},
	{
		ID: "vm-multiplex-brutal", VPNName: "vm-brutal", Port: 4452,
		Extra: append(append([]string{}, tlsNameFlag...),
			"--multiplex", "--multiplex-brutal",
			"--multiplex-brutal-up-mbps", "100", "--multiplex-brutal-down-mbps", "100"),
		Multiplex: true, MultiplexBrutal: true,
		MultiplexBrutalUpMbps: 100, MultiplexBrutalDownMbps: 100,
		SkipConnect: true,
	},
}

func TestVMessConnect(t *testing.T) {
	r := runner.NewRunner(t, e2eEnv)

	for _, tc := range cases {
		t.Run(tc.ID, func(t *testing.T) {
			result, err := r.CreateVPNFull(tc.VPNName, "vmess", tc.Port, tc.Extra...)
			if err != nil {
				t.Fatalf("create vpn: %v", err)
			}
			t.Cleanup(func() {
				if err := r.DeleteVPN(tc.VPNName); err != nil {
					t.Errorf("delete vpn %q: %v", tc.VPNName, err)
				}
			})

			if !strings.HasPrefix(result.URI, "vmess://") {
				t.Fatalf("expected vmess URI, got %q", result.URI)
			}

			data, err := vmess.ParseProtocolData(result.VPN.ProtocolData)
			if err != nil {
				t.Fatalf("parse protocol data: %v", err)
			}
			if data.TLSDisabled != tc.NoTLS {
				t.Fatalf("tls disabled: got %v want %v", data.TLSDisabled, tc.NoTLS)
			}
			if data.RealityEnabled != tc.Reality {
				t.Fatalf("reality flag: got %v want %v", data.RealityEnabled, tc.Reality)
			}
			if tc.WantAlterID != 0 && data.DefaultAlterId != tc.WantAlterID {
				t.Fatalf("default alter id: got %d want %d", data.DefaultAlterId, tc.WantAlterID)
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

			cfg, err := runner.VMessConnectConfigFromCreate(
				result, tc.Multiplex, tc.MultiplexPadding, tc.MultiplexBrutal,
				tc.MultiplexBrutalUpMbps, tc.MultiplexBrutalDownMbps,
			)
			if err != nil {
				t.Fatalf("connect config: %v", err)
			}
			if tc.WantAlterID != 0 && cfg.AlterID != tc.WantAlterID {
				t.Fatalf("alter id: got %d want %d", cfg.AlterID, tc.WantAlterID)
			}

			if tc.SkipConnect {
				if err := r.CheckVMessClientConfig(cfg); err != nil {
					t.Fatalf("check vmess client config: %v", err)
				}
				return
			}

			if err := r.CurlViaVmess(cfg); err != nil {
				t.Fatalf("curl via vmess: %v", err)
			}
		})
	}
}
