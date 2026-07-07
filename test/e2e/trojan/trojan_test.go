//go:build e2e

package trojan_test

import (
	"os"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/test/e2e/runner"
)

const tlsServerName = "e2e-server"

var trojanUFWPorts = []int{443, 444, 4443, 4444, 4450, 8443, 8444, 8445, 8446, 8447}

var e2eEnv = runner.NewEnv(runner.Config{
	ProjectName: "obscura-e2e-trojan",
	UFWPorts:    trojanUFWPorts,
	UFWUDPPorts: []int{8447},
})

func TestMain(m *testing.M) {
	os.Exit(runner.RunMain(runner.Config{
		ProjectName: "obscura-e2e-trojan",
		UFWPorts:    trojanUFWPorts,
		UFWUDPPorts: []int{8447},
	}, m))
}

// TrojanCase describes a declarative Trojan E2E scenario.
type TrojanCase struct {
	ID               string
	VPNName          string
	Port             int
	Extra            []string
	Multiplex        bool
	MultiplexPadding bool
	Reality          bool
}

var tlsNameFlag = []string{"--tls-server-name", tlsServerName}

var cases = []TrojanCase{
	{
		ID: "tr-basic", VPNName: "tr", Port: 443,
		Extra: append([]string{}, tlsNameFlag...),
	},
	{
		ID: "tr-multiplex", VPNName: "tr-mux", Port: 4443,
		Extra:     append(append([]string{}, tlsNameFlag...), "--multiplex"),
		Multiplex: true,
	},
	{
		ID: "tr-multiplex-padding", VPNName: "tr-mux-pad", Port: 4444,
		Extra:     append(append([]string{}, tlsNameFlag...), "--multiplex", "--multiplex-padding"),
		Multiplex: true, MultiplexPadding: true,
	},
	{
		ID: "tr-ws", VPNName: "tr-ws", Port: 8443,
		Extra: append(append([]string{}, tlsNameFlag...), "--transport", "ws", "--transport-path", "/video"),
	},
	{
		ID: "tr-grpc", VPNName: "tr-grpc", Port: 8444,
		Extra: append(append([]string{}, tlsNameFlag...), "--transport", "grpc", "--transport-service-name", "TunService"),
	},
	{
		ID: "tr-http", VPNName: "tr-http", Port: 8445,
		Extra: append(append([]string{}, tlsNameFlag...), "--transport", "http", "--transport-path", "/api"),
	},
	{
		ID: "tr-httpupgrade", VPNName: "tr-hu", Port: 8446,
		Extra: append(append([]string{}, tlsNameFlag...), "--transport", "httpupgrade", "--transport-path", "/up"),
	},
	{
		ID: "tr-quic", VPNName: "tr-quic", Port: 8447,
		Extra: append(append([]string{}, tlsNameFlag...), "--transport", "quic"),
	},
	{
		ID: "tr-reality", VPNName: "tr-st", Port: 444,
		Extra:   []string{"--reality", "--reality-handshake", "www.bing.com"},
		Reality: true,
	},
	{
		ID: "tr-fallback-stub", VPNName: "tr-fb", Port: 4450,
		Extra: append(append([]string{}, tlsNameFlag...), "--fallback-stub"),
	},
}

func TestTrojanConnect(t *testing.T) {
	r := runner.NewRunner(t, e2eEnv)

	for _, tc := range cases {
		t.Run(tc.ID, func(t *testing.T) {
			result, err := r.CreateVPNFull(tc.VPNName, "trojan", tc.Port, tc.Extra...)
			if err != nil {
				t.Fatalf("create vpn: %v", err)
			}
			t.Cleanup(func() {
				if err := r.DeleteVPN(tc.VPNName); err != nil {
					t.Errorf("delete vpn %q: %v", tc.VPNName, err)
				}
			})

			if !strings.HasPrefix(result.URI, "trojan://") {
				t.Fatalf("expected trojan URI, got %q", result.URI)
			}
			if !strings.Contains(result.URI, runner.ServerHost) {
				t.Fatalf("expected client host %q in uri, got %q", runner.ServerHost, result.URI)
			}

			cfg, err := runner.TrojanConnectConfigFromCreate(result, tc.Multiplex, tc.MultiplexPadding)
			if err != nil {
				t.Fatalf("connect config: %v", err)
			}
			if cfg.Data.RealityEnabled != tc.Reality {
				t.Fatalf("reality flag: got %v want %v", cfg.Data.RealityEnabled, tc.Reality)
			}

			if err := r.CurlViaTrojan(cfg); err != nil {
				t.Fatalf("curl via trojan: %v", err)
			}
		})
	}
}
