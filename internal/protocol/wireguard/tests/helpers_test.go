package wireguard_test

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/wireguard"
)

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

func mustKeypair(t *testing.T) (priv, pub string) {
	t.Helper()
	pair, err := wireguard.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return pair.PrivateKey, pair.PublicKey
}

func mustProtocolData(t *testing.T, serverPriv, serverPub string, extra wireguard.ProtocolData) []byte {
	t.Helper()
	data := wireguard.ProtocolData{
		PrivateKey: serverPriv,
		PublicKey:  serverPub,
		Address:    []string{"10.8.0.1/24"},
	}
	if len(extra.Address) > 0 {
		data.Address = extra.Address
	}
	if extra.MTU != 0 {
		data.MTU = extra.MTU
	}
	if extra.PeerPreSharedKey != "" {
		data.PeerPreSharedKey = extra.PeerPreSharedKey
	}
	if extra.PeerPersistentKeepaliveInterval != 0 {
		data.PeerPersistentKeepaliveInterval = extra.PeerPersistentKeepaliveInterval
	}
	if len(extra.PeerReserved) > 0 {
		data.PeerReserved = extra.PeerReserved
	}
	if len(extra.ClientAllowedIPs) > 0 {
		data.ClientAllowedIPs = extra.ClientAllowedIPs
	}
	raw, err := wireguard.MarshalProtocolData(data)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testVPN(t *testing.T, protocolData []byte) domain.VPNConfig {
	t.Helper()
	return domain.VPNConfig{
		Name:         "wg",
		Protocol:     "wireguard",
		Tag:          "vpn-wg",
		Enabled:      true,
		Listen:       domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 51820},
		ProtocolData: protocolData,
	}
}

func testClient(t *testing.T, name string) domain.ClientConfig {
	t.Helper()
	priv, pub := mustKeypair(t)
	return domain.ClientConfig{Name: name, Username: pub, Password: priv, Enabled: true}
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
	delete(gotMap, "private_key")
	delete(wantMap, "private_key")
	if peers, ok := gotMap["peers"].([]any); ok {
		for _, p := range peers {
			if peer, ok := p.(map[string]any); ok {
				delete(peer, "public_key")
			}
		}
	}
	if peers, ok := wantMap["peers"].([]any); ok {
		for _, p := range peers {
			if peer, ok := p.(map[string]any); ok {
				delete(peer, "public_key")
			}
		}
	}
	if diff := cmp.Diff(wantMap, gotMap); diff != "" {
		t.Fatalf("golden mismatch (-want +got):\n%s", diff)
	}
}
