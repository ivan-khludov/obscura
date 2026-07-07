package vmess_test

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/ivan-khludov/obscura/internal/protocol/testutil"
	"github.com/ivan-khludov/obscura/internal/protocol/vmess"
)

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("rand failed") }

const sampleRealityOutput = "PrivateKey: priv\nPublicKey: pub\n"

const sampleECHOutput = `-----BEGIN ECH KEYS-----
AQIDBAUGBwg=
-----END ECH KEYS-----
`

type errBuildContext struct {
	*testutil.BuildContext
	saveErr bool
}

func (c *errBuildContext) SaveManifest() error {
	if c.saveErr {
		return errors.New("manifest save failed")
	}
	return c.BuildContext.SaveManifest()
}

func newErrBuildContext(dataDir string, saveErr bool) *errBuildContext {
	return &errBuildContext{BuildContext: testutil.NewBuildContext(dataDir), saveErr: saveErr}
}

func parseHookFailOnSecond() func([]byte) (vmess.ProtocolData, error) {
	calls := 0
	return func(raw []byte) (vmess.ProtocolData, error) {
		calls++
		if calls >= 2 {
			return vmess.ProtocolData{}, errors.New("parse failed")
		}
		if len(raw) == 0 {
			return vmess.ProtocolData{}, nil
		}
		var data vmess.ProtocolData
		if err := json.Unmarshal(raw, &data); err != nil {
			return vmess.ProtocolData{}, err
		}
		return data, nil
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
	delete(gotMap, "users")
	delete(wantMap, "users")
	if tls, ok := gotMap["tls"].(map[string]any); ok {
		delete(tls, "certificate_path")
		delete(tls, "key_path")
	}
	if tls, ok := wantMap["tls"].(map[string]any); ok {
		delete(tls, "certificate_path")
		delete(tls, "key_path")
	}
	if diff := cmp.Diff(wantMap, gotMap); diff != "" {
		t.Fatalf("golden mismatch (-want +got):\n%s", diff)
	}
}
