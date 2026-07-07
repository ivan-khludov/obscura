//go:build e2e

package http_test

import (
	"os"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/test/e2e/runner"
)

var e2eEnv = runner.NewEnv(runner.Config{
	ProjectName: "obscura-e2e-http",
	UFWPorts:    []int{8080, 8443},
})

func TestMain(m *testing.M) {
	os.Exit(runner.RunMain(runner.Config{
		ProjectName: "obscura-e2e-http",
		UFWPorts:    []int{8080, 8443},
	}, m))
}

// HTTPCase describes a declarative HTTP proxy E2E scenario.
type HTTPCase struct {
	ID           string
	VPNName      string
	Port         int
	TLS          bool
	CurlInsecure bool
	Scheme       string
}

var cases = []HTTPCase{
	{ID: "http-plain", VPNName: "web", Port: 8080, Scheme: "http"},
	{ID: "http-tls", VPNName: "secure", Port: 8443, TLS: true, CurlInsecure: true, Scheme: "https"},
}

func TestHTTPProxyConnect(t *testing.T) {
	r := runner.NewRunner(t, e2eEnv)

	for _, tc := range cases {
		t.Run(tc.ID, func(t *testing.T) {
			extra := []string{}
			if tc.TLS {
				extra = append(extra, "--tls")
			}
			uri, err := r.CreateVPN(tc.VPNName, "http", tc.Port, extra...)
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

			if err := r.CurlViaProxy(uri, tc.CurlInsecure); err != nil {
				t.Fatalf("curl via proxy: %v", err)
			}
		})
	}
}
