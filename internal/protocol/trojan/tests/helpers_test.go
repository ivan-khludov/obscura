package trojan_test

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/trojan"
)

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func validCertData(t *testing.T) []byte {
	t.Helper()
	raw, err := trojan.MarshalProtocolData(trojan.ProtocolData{
		CertPath:   "/etc/obscura/certs/vpn-main.crt",
		KeyPath:    "/etc/obscura/certs/vpn-main.key",
		ServerName: "example.com",
		ALPN:       []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testVPN(t *testing.T, protocolData []byte) domain.VPNConfig {
	t.Helper()
	return domain.VPNConfig{
		Name:         "main",
		Protocol:     "trojan",
		Tag:          "vpn-main",
		Enabled:      true,
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: protocolData,
	}
}

func assertGolden(t *testing.T, golden string, got map[string]any) {
	t.Helper()
	raw, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(golden, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden: %v (run with UPDATE_GOLDEN=1)", err)
	}
	var gotMap, wantMap map[string]any
	if err := json.Unmarshal(raw, &gotMap); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(want, &wantMap); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(wantMap, gotMap); diff != "" {
		t.Fatalf("golden mismatch (-want +got):\n%s", diff)
	}
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if p != "" && !contains(s, p) {
			return false
		}
	}
	return true
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

const sampleRealityOutput = "PrivateKey: UuMBgl7MXTPx9inmQp2UC7Jcnwc6XYbwDNebonM-FCc\nPublicKey: jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0\n"

const sampleECHOutput = `-----BEGIN ECH KEYS-----
AQIDBAUGBwg=
-----END ECH KEYS-----
`
