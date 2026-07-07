//go:build e2e

package shadowsocks_test

import (
	"os"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/test/e2e/runner"
)

var e2eEnv = runner.NewEnv(runner.Config{
	ProjectName: "obscura-e2e-shadowsocks",
	UFWPorts:    []int{8388, 8389, 443},
})

func TestMain(m *testing.M) {
	os.Exit(runner.RunMain(runner.Config{
		ProjectName: "obscura-e2e-shadowsocks",
		UFWPorts:    []int{8388, 8389, 443},
	}, m))
}

// SSCase describes a declarative Shadowsocks E2E scenario.
type SSCase struct {
	ID               string
	VPNName          string
	Port             int
	Extra            []string
	Multiplex        bool
	MultiplexPadding bool
	ShadowTLS        bool
}

var cases = []SSCase{
	{
		ID: "ss-basic", VPNName: "ss", Port: 8388,
		Extra: []string{"--method", "2022-blake3-aes-128-gcm"},
	},
	{
		ID: "ss-multiplex", VPNName: "ss-mux", Port: 8389,
		Extra:     []string{"--multiplex"},
		Multiplex: true,
	},
	{
		ID: "ss-shadowtls", VPNName: "ss-st", Port: 443,
		Extra:     []string{"--shadowtls", "--shadowtls-handshake", runner.ShadowTLSHandshakeHost},
		ShadowTLS: true,
	},
}

func TestShadowsocksConnect(t *testing.T) {
	r := runner.NewRunner(t, e2eEnv)

	for _, tc := range cases {
		t.Run(tc.ID, func(t *testing.T) {
			result, err := r.CreateVPNFull(tc.VPNName, "shadowsocks", tc.Port, tc.Extra...)
			if err != nil {
				t.Fatalf("create vpn: %v", err)
			}
			t.Cleanup(func() {
				if err := r.DeleteVPN(tc.VPNName); err != nil {
					t.Errorf("delete vpn %q: %v", tc.VPNName, err)
				}
			})

			if !strings.HasPrefix(result.URI, "ss://") {
				t.Fatalf("expected ss URI, got %q", result.URI)
			}
			if !strings.Contains(result.URI, runner.ServerHost) {
				t.Fatalf("expected client host %q in uri, got %q", runner.ServerHost, result.URI)
			}

			cfg, err := runner.SSConnectConfigFromCreate(result, tc.Multiplex, tc.MultiplexPadding)
			if err != nil {
				t.Fatalf("connect config: %v", err)
			}
			if cfg.ShadowTLS != tc.ShadowTLS {
				t.Fatalf("shadowtls flag: got %v want %v", cfg.ShadowTLS, tc.ShadowTLS)
			}

			if err := r.CurlViaShadowsocks(cfg); err != nil {
				t.Fatalf("curl via shadowsocks: %v", err)
			}
		})
	}
}
