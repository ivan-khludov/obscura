package vless_test

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/testutil"
	"github.com/ivan-khludov/obscura/internal/protocol/vless"
)

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("rand failed") }

const sampleRealityOutput = "PrivateKey: priv\nPublicKey: pub\n"

const sampleECHOutput = `-----BEGIN ECH KEYS-----
AQIDBAUGBwg=
-----END ECH KEYS-----
`

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

func validCertVPN(t *testing.T) (domain.VPNConfig, domain.ClientConfig) {
	t.Helper()
	raw, err := vless.MarshalProtocolData(vless.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	return domain.VPNConfig{
			Name: "main", Tag: "vpn-main",
			Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
			ProtocolData: raw,
		}, domain.ClientConfig{
			Name: "phone", Password: uuid.NewString(), Enabled: true,
		}
}

func flowConflictVPN(t *testing.T) (domain.VPNConfig, domain.ClientConfig) {
	t.Helper()
	raw, err := vless.MarshalProtocolData(vless.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key",
		TransportType: "ws", TransportWS: &vless.TransportWS{Path: "/"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return domain.VPNConfig{
			Name: "main", Tag: "vpn-main",
			Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
			ProtocolData: raw,
		}, domain.ClientConfig{
			Name: "phone", Password: uuid.NewString(), Username: vless.FlowVision, Enabled: true,
		}
}

func parseHookFailOnSecond() func([]byte) (vless.ProtocolData, error) {
	calls := 0
	return func(raw []byte) (vless.ProtocolData, error) {
		calls++
		if calls >= 2 {
			return vless.ProtocolData{}, errors.New("parse failed")
		}
		if len(raw) == 0 {
			return vless.ProtocolData{}, nil
		}
		var data vless.ProtocolData
		if err := json.Unmarshal(raw, &data); err != nil {
			return vless.ProtocolData{}, err
		}
		return data, nil
	}
}

func parseHookFlowConflictOnSecond() func([]byte) (vless.ProtocolData, error) {
	calls := 0
	return func(raw []byte) (vless.ProtocolData, error) {
		calls++
		if calls >= 2 {
			return vless.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key",
				DefaultFlow:   vless.FlowVision,
				TransportType: "ws", TransportWS: &vless.TransportWS{Path: "/"},
			}, nil
		}
		if len(raw) == 0 {
			return vless.ProtocolData{}, nil
		}
		var data vless.ProtocolData
		if err := json.Unmarshal(raw, &data); err != nil {
			return vless.ProtocolData{}, err
		}
		return data, nil
	}
}
