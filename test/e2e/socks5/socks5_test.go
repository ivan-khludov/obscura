//go:build e2e

package socks5_test

import (
	"os"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/test/e2e/runner"
)

var e2eEnv = runner.NewEnv(runner.Config{
	ProjectName: "obscura-e2e-socks5",
	UFWPorts:    []int{1080},
})

func TestMain(m *testing.M) {
	os.Exit(runner.RunMain(runner.Config{
		ProjectName: "obscura-e2e-socks5",
		UFWPorts:    []int{1080},
	}, m))
}

// Socks5Case describes a declarative SOCKS5 E2E scenario.
type Socks5Case struct {
	ID      string
	VPNName string
	Port    int
	Scheme  string
}

var cases = []Socks5Case{
	{ID: "socks5-basic", VPNName: "main", Port: 1080, Scheme: "socks5"},
}

func TestSocks5ProxyConnect(t *testing.T) {
	r := runner.NewRunner(t, e2eEnv)

	for _, tc := range cases {
		t.Run(tc.ID, func(t *testing.T) {
			uri, err := r.CreateVPN(tc.VPNName, "socks5", tc.Port)
			if err != nil {
				t.Fatalf("create vpn: %v", err)
			}
			t.Cleanup(func() {
				if err := r.DeleteVPN(tc.VPNName); err != nil {
					t.Errorf("delete vpn %q: %v", tc.VPNName, err)
				}
			})

			if !strings.HasPrefix(uri, tc.Scheme+"://") {
				t.Fatalf("expected %s URI, got %q", tc.Scheme, uri)
			}
			if !strings.Contains(uri, runner.ServerHost) {
				t.Fatalf("expected client host %q in uri, got %q", runner.ServerHost, uri)
			}

			if err := r.CurlViaProxy(uri, false); err != nil {
				t.Fatalf("curl via proxy: %v", err)
			}
		})
	}
}
