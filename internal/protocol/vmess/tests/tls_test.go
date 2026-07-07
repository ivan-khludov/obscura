package vmess_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol/vmess"
)

func TestParseRealityKeypairOutput_colonFormat(t *testing.T) {
	pair, err := vmess.ParseRealityKeypairOutput(sampleRealityOutput)
	if err != nil {
		t.Fatal(err)
	}
	if pair.PrivateKey != "priv" || pair.PublicKey != "pub" {
		t.Fatalf("unexpected pair: %#v", pair)
	}
}

func TestParseRealityKeypairOutput_spaceFormat(t *testing.T) {
	out := "Private key: priv\nPublic key: pub\n"
	pair, err := vmess.ParseRealityKeypairOutput(out)
	if err != nil {
		t.Fatal(err)
	}
	if pair.PrivateKey != "priv" || pair.PublicKey != "pub" {
		t.Fatalf("unexpected pair: %#v", pair)
	}
}

func TestParseRealityKeypairOutput_jsonFormat(t *testing.T) {
	out := `{"private_key":"priv","public_key":"pub"}`
	pair, err := vmess.ParseRealityKeypairOutput(out)
	if err != nil {
		t.Fatal(err)
	}
	if pair.PrivateKey != "priv" {
		t.Fatalf("unexpected pair: %#v", pair)
	}
}

func TestParseRealityKeypairOutput_invalid(t *testing.T) {
	_, err := vmess.ParseRealityKeypairOutput("garbage")
	if err == nil || !strings.Contains(err.Error(), "parse reality keypair") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTLSGen_GenerateRealityKeypair_ok(t *testing.T) {
	gen := &vmess.TLSGen{
		RunCommand: func(string, ...string) ([]byte, error) {
			return []byte(sampleRealityOutput), nil
		},
	}
	pair, err := gen.GenerateRealityKeypair("sing-box")
	if err != nil {
		t.Fatal(err)
	}
	if pair.PrivateKey != "priv" {
		t.Fatalf("unexpected pair: %#v", pair)
	}
}

func TestTLSGen_GenerateRealityKeypair_defaultPath(t *testing.T) {
	called := false
	gen := &vmess.TLSGen{
		RunCommand: func(name string, args ...string) ([]byte, error) {
			called = true
			if name != "sing-box" {
				t.Fatalf("name = %q", name)
			}
			return []byte(sampleRealityOutput), nil
		},
	}
	if _, err := gen.GenerateRealityKeypair(""); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("expected runCommand call")
	}
}

func TestTLSGen_GenerateRealityKeypair_execError(t *testing.T) {
	gen := &vmess.TLSGen{
		RunCommand: func(string, ...string) ([]byte, error) {
			return []byte("boom"), errors.New("exec failed")
		},
	}
	_, err := gen.GenerateRealityKeypair("sing-box")
	if err == nil || !strings.Contains(err.Error(), "sing-box generate reality-keypair") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGenerateRealityKeypair_packageFunc(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "sing-box")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s' '"+sampleRealityOutput+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	pair, err := vmess.GenerateRealityKeypair(script)
	if err != nil || pair.PrivateKey != "priv" {
		t.Fatalf("GenerateRealityKeypair() = %#v, %v", pair, err)
	}
}

func TestTLSGen_GenerateRealityShortID_ok(t *testing.T) {
	gen := &vmess.TLSGen{}
	id, err := gen.GenerateRealityShortID()
	if err != nil {
		t.Fatal(err)
	}
	if len(id) == 0 || len(id) > 8 {
		t.Fatalf("unexpected short_id: %q", id)
	}
}

func TestTLSGen_GenerateRealityShortID_randError(t *testing.T) {
	gen := &vmess.TLSGen{RandRead: failReader{}}
	_, err := gen.GenerateRealityShortID()
	if err == nil || !strings.Contains(err.Error(), "generate reality short_id") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTLSGen_nilReceiver(t *testing.T) {
	var gen *vmess.TLSGen
	id, err := gen.GenerateRealityShortID()
	if err != nil || id == "" {
		t.Fatalf("GenerateRealityShortID() = %q, %v", id, err)
	}
}

func TestGenerateRealityShortID_packageFunc(t *testing.T) {
	id, err := vmess.GenerateRealityShortID()
	if err != nil || id == "" {
		t.Fatalf("GenerateRealityShortID() = %q, %v", id, err)
	}
}

func TestTLSGen_GenerateECHKeypair_ok(t *testing.T) {
	dir := t.TempDir()
	keyPath := dir + "/ech.key"
	gen := &vmess.TLSGen{
		RunCommand: func(string, ...string) ([]byte, error) {
			return []byte(sampleECHOutput), nil
		},
	}
	pair, err := gen.GenerateECHKeypair("sing-box", "example.com", keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if pair.KeyPath != keyPath {
		t.Fatalf("unexpected key path: %q", pair.KeyPath)
	}
}

func TestGenerateECHKeypair_packageFunc(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ech.key")
	script := filepath.Join(dir, "sing-box")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s' '"+sampleECHOutput+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	pair, err := vmess.GenerateECHKeypair(script, "example.com", keyPath)
	if err != nil || pair.KeyPath != keyPath {
		t.Fatalf("GenerateECHKeypair() = %#v, %v", pair, err)
	}
}

func TestTLSGen_GenerateECHKeypair_error(t *testing.T) {
	gen := &vmess.TLSGen{
		RunCommand: func(string, ...string) ([]byte, error) {
			return nil, errors.New("ech failed")
		},
	}
	_, err := gen.GenerateECHKeypair("sing-box", "example.com", t.TempDir()+"/k")
	if err == nil {
		t.Fatal("expected error")
	}
}
