package tuic_test

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/testutil"
	"github.com/ivan-khludov/obscura/internal/protocol/tuic"
)

const testUUID = "059032A9-7D40-4A96-9BB1-36823D848068"

type manifestErrContext struct {
	*testutil.BuildContext
	saveErr error
}

func (c *manifestErrContext) SaveManifest() error {
	if c.saveErr != nil {
		return c.saveErr
	}
	return c.BuildContext.SaveManifest()
}

func newManifestErrContext(dataDir string, saveErr error) *manifestErrContext {
	return &manifestErrContext{
		BuildContext: testutil.NewBuildContext(dataDir),
		saveErr:      saveErr,
	}
}

func mustProtocolData(t *testing.T, data any) []byte {
	t.Helper()
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func validCertData(t *testing.T) []byte {
	t.Helper()
	return mustProtocolData(t, map[string]any{
		"cert_path":   "/etc/obscura/certs/vpn-main.crt",
		"key_path":    "/etc/obscura/certs/vpn-main.key",
		"server_name": "example.com",
		"alpn":        []string{"h3"},
	})
}

func testVPN(t *testing.T, protocolData []byte) domain.VPNConfig {
	t.Helper()
	return domain.VPNConfig{
		Name:         "main",
		Protocol:     "tuic",
		Tag:          "vpn-main",
		Enabled:      true,
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		ProtocolData: protocolData,
	}
}

func testClient(name, password string) domain.ClientConfig {
	return domain.ClientConfig{Name: name, Username: testUUID, Password: password, Enabled: true}
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
		if !contains(s, p) {
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

func errSaveManifest() error {
	return errors.New("save manifest failed")
}

const sampleECHOutput = `-----BEGIN ECH KEYS-----
AQIDBAUGBwg=
-----END ECH KEYS-----
`

func parseHookFailOnSecond() func([]byte) (tuic.ProtocolData, error) {
	calls := 0
	return func(raw []byte) (tuic.ProtocolData, error) {
		calls++
		if calls >= 2 {
			return tuic.ProtocolData{}, errors.New("parse failed")
		}
		return tuic.ParseProtocolData(raw)
	}
}
