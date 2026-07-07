package trojan_test

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol/trojan"
)

func TestGenerateRealityKeypair_withDI(t *testing.T) {
	g := &trojan.TLSGen{
		RunCommand: func(_ string, args ...string) ([]byte, error) {
			if len(args) >= 2 && args[0] == "generate" && args[1] == "reality-keypair" {
				return []byte(sampleRealityOutput), nil
			}
			return nil, errors.New("unexpected")
		},
	}
	pair, err := g.GenerateRealityKeypair("sing-box")
	if err != nil {
		t.Fatal(err)
	}
	if pair.PrivateKey == "" || pair.PublicKey == "" {
		t.Fatalf("unexpected pair: %#v", pair)
	}
}

func TestGenerateRealityKeypair_packageFunc(t *testing.T) {
	reset := trojan.SetTLSGenProviderForTest(func() *trojan.TLSGen {
		return &trojan.TLSGen{
			RunCommand: func(string, ...string) ([]byte, error) {
				return []byte(sampleRealityOutput), nil
			},
		}
	})
	defer reset()
	pair, err := trojan.GenerateRealityKeypair("sing-box")
	if err != nil {
		t.Fatal(err)
	}
	if pair.PrivateKey == "" {
		t.Fatal("expected private key")
	}
}

func TestGenerateRealityKeypair_defaults(t *testing.T) {
	g := &trojan.TLSGen{
		RunCommand: func(name string, args ...string) ([]byte, error) {
			if name != "sing-box" {
				t.Fatalf("default binary = %q", name)
			}
			return []byte(sampleRealityOutput), nil
		},
	}
	if _, err := g.GenerateRealityKeypair(""); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateRealityKeypair_execError(t *testing.T) {
	g := &trojan.TLSGen{
		RunCommand: func(string, ...string) ([]byte, error) {
			return []byte("boom"), errors.New("exec failed")
		},
	}
	_, err := g.GenerateRealityKeypair("sing-box")
	if err == nil || !strings.Contains(err.Error(), "sing-box generate reality-keypair") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseRealityKeypair_allFormats(t *testing.T) {
	cases := []string{
		sampleRealityOutput,
		"Private key: UuMBgl7MXTPx9inmQp2UC7Jcnwc6XYbwDNebonM-FCc\nPublic key: jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0\n",
		`{"private_key":"UuMBgl7MXTPx9inmQp2UC7Jcnwc6XYbwDNebonM-FCc","public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"}`,
	}
	for i, out := range cases {
		pair, err := trojan.ParseRealityKeypairOutput(out)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if pair.PrivateKey == "" {
			t.Fatalf("case %d: empty private key", i)
		}
	}
	_, err := trojan.ParseRealityKeypairOutput("garbage")
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestRealityPublicKeyFromPrivate(t *testing.T) {
	pair, err := trojan.ParseRealityKeypairOutput(sampleRealityOutput)
	if err != nil {
		t.Fatal(err)
	}
	got, err := trojan.RealityPublicKeyFromPrivate(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if got != pair.PublicKey {
		t.Fatalf("public key mismatch: got %q want %q", got, pair.PublicKey)
	}
}

func TestRealityPublicKeyFromPrivate_generated(t *testing.T) {
	reset := trojan.SetTLSGenProviderForTest(func() *trojan.TLSGen {
		return &trojan.TLSGen{
			RunCommand: func(string, ...string) ([]byte, error) {
				return []byte(sampleRealityOutput), nil
			},
		}
	})
	defer reset()
	pair, err := trojan.GenerateRealityKeypair("sing-box")
	if err != nil {
		t.Fatal(err)
	}
	got, err := trojan.RealityPublicKeyFromPrivate(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if got != pair.PublicKey {
		t.Fatalf("public key mismatch: derived %q want %q", got, pair.PublicKey)
	}
}

func TestRealityPublicKeyFromPrivate_invalid(t *testing.T) {
	if _, err := trojan.RealityPublicKeyFromPrivate("not-a-key"); err == nil {
		t.Fatal("expected error for invalid key")
	}
}

func TestRealityPublicKeyFromPrivate_allEncodings(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.StdEncoding,
		base64.RawStdEncoding,
	} {
		key := enc.EncodeToString(raw)
		if _, err := trojan.RealityPublicKeyFromPrivate(key); err != nil {
			t.Fatalf("encoding %T: %v", enc, err)
		}
	}
}

func TestGenerateRealityShortID(t *testing.T) {
	g := &trojan.TLSGen{RandRead: strings.NewReader("abcd1234")}
	id, err := g.GenerateRealityShortID()
	if err != nil {
		t.Fatal(err)
	}
	if id != "61626364" {
		t.Fatalf("unexpected short_id: %q", id)
	}
	id, err = trojan.GenerateRealityShortID()
	if err != nil {
		t.Fatal(err)
	}
	if len(id) == 0 || len(id) > 8 {
		t.Fatalf("unexpected short_id: %q", id)
	}
}

func TestGenerateRealityShortID_readError(t *testing.T) {
	g := &trojan.TLSGen{RandRead: errReader{}}
	_, err := g.GenerateRealityShortID()
	if err == nil || !strings.Contains(err.Error(), "generate reality short_id") {
		t.Fatalf("unexpected error: %v", err)
	}
	reset := trojan.SetTLSGenProviderForTest(func() *trojan.TLSGen {
		return &trojan.TLSGen{RandRead: errReader{}}
	})
	defer reset()
	_, err = trojan.GenerateRealityShortID()
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGenerateECHKeypair_withDI(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ech.key")
	g := &trojan.TLSGen{
		RunCommand: func(string, ...string) ([]byte, error) {
			return []byte(sampleECHOutput), nil
		},
	}
	reset := trojan.SetTLSGenProviderForTest(func() *trojan.TLSGen { return g })
	defer reset()
	pair, err := g.GenerateECHKeypair("sing-box", "example.com", keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if pair.KeyPath != keyPath {
		t.Fatalf("key path = %q", pair.KeyPath)
	}
}

func TestGenerateECHKeypair_packageFunc(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ech.key")
	reset := trojan.SetTLSGenProviderForTest(func() *trojan.TLSGen {
		return &trojan.TLSGen{
			RunCommand: func(string, ...string) ([]byte, error) {
				return []byte(sampleECHOutput), nil
			},
		}
	})
	defer reset()
	pair, err := trojan.GenerateECHKeypair("sing-box", "example.com", keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if pair.KeyPath != keyPath {
		t.Fatalf("key path = %q", pair.KeyPath)
	}
}

func TestGenerateECHKeypair_realSingBox(t *testing.T) {
	if _, err := exec.LookPath("sing-box"); err != nil {
		t.Skip("sing-box not installed")
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ech.key")
	pair, err := trojan.GenerateECHKeypair("sing-box", "example.com", keyPath)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(pair.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "ECH KEYS") {
		t.Fatalf("unexpected key file: %q", raw)
	}
}

func TestGenerateRealityKeypair_zeroValueExecPath(t *testing.T) {
	prev := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", prev) })
	binDir := t.TempDir()
	script := filepath.Join(binDir, "sing-box")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s' '"+sampleRealityOutput+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Setenv("PATH", binDir+string(os.PathListSeparator)+prev)
	reset := trojan.SetTLSGenProviderForTest(func() *trojan.TLSGen { return &trojan.TLSGen{} })
	defer reset()
	pair, err := trojan.GenerateRealityKeypair("")
	if err != nil {
		t.Fatal(err)
	}
	if pair.PrivateKey == "" {
		t.Fatal("expected private key from exec path")
	}
}

func TestGenerateRealityKeypair_realSingBox(t *testing.T) {
	if _, err := exec.LookPath("sing-box"); err != nil {
		t.Skip("sing-box not installed")
	}
	pair, err := trojan.GenerateRealityKeypair("sing-box")
	if err != nil {
		t.Fatal(err)
	}
	got, err := trojan.RealityPublicKeyFromPrivate(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if got != pair.PublicKey {
		t.Fatalf("public key mismatch: derived %q want %q", got, pair.PublicKey)
	}
}

func TestParseRealityKeypair_jsonOnlyPublic(t *testing.T) {
	out := `{"public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"}`
	_, err := trojan.ParseRealityKeypairOutput(out)
	if err == nil {
		t.Fatal("expected error without private key")
	}
}

func TestParseRealityKeypair_invalidJSON(t *testing.T) {
	_, err := trojan.ParseRealityKeypairOutput(`not json and no keys`)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRealityPublicKeyFromPrivate_invalidPrivateKey(t *testing.T) {
	reset := trojan.SetNewRealityPrivateKeyForTest(func([]byte) (*ecdh.PrivateKey, error) {
		return nil, errors.New("bad key")
	})
	defer reset()
	pair, err := trojan.ParseRealityKeypairOutput(sampleRealityOutput)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trojan.RealityPublicKeyFromPrivate(pair.PrivateKey); err == nil || !strings.Contains(err.Error(), "invalid reality private key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRealityPublicKeyFromPrivate_wrongLength(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3})
	if _, err := trojan.RealityPublicKeyFromPrivate(key); err == nil {
		t.Fatal("expected decode error for short key")
	}
}

func TestGenerateECHKeypair_error(t *testing.T) {
	reset := trojan.SetTLSGenProviderForTest(func() *trojan.TLSGen {
		return &trojan.TLSGen{
			RunCommand: func(string, ...string) ([]byte, error) {
				return nil, errors.New("ech failed")
			},
		}
	})
	defer reset()
	_, err := trojan.GenerateECHKeypair("sing-box", "example.com", filepath.Join(t.TempDir(), "k"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseRealityKeypairOutput_jsonMarshalRoundTrip(t *testing.T) {
	var m map[string]string
	if err := json.Unmarshal([]byte(`{"private_key":"UuMBgl7MXTPx9inmQp2UC7Jcnwc6XYbwDNebonM-FCc"}`), &m); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(m)
	pair, err := trojan.ParseRealityKeypairOutput(string(raw))
	if err != nil || pair.PrivateKey == "" {
		t.Fatalf("pair = %#v, err = %v", pair, err)
	}
}
