package hysteria2_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol/hysteria2"
)

func TestGenerateECHKeypair_ok(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ech.key")
	restore := hysteria2.SetTLSGenFactoryForTest(func() *hysteria2.TLSGen {
		return &hysteria2.TLSGen{
			RunCommand: func(string, ...string) ([]byte, error) {
				return []byte(sampleECHOutput), nil
			},
		}
	})
	defer restore()
	pair, err := hysteria2.GenerateECHKeypair("sing-box", "example.com", keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if pair.KeyPath != keyPath {
		t.Fatalf("pair = %#v", pair)
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "ECH KEYS") {
		t.Fatalf("unexpected key: %q", raw)
	}
}

func TestTLSGen_method(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ech.key")
	gen := &hysteria2.TLSGen{
		RunCommand: func(string, ...string) ([]byte, error) {
			return []byte(sampleECHOutput), nil
		},
	}
	pair, err := gen.GenerateECHKeypair("sing-box", "example.com", keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if pair.KeyPath != keyPath {
		t.Fatalf("pair = %#v", pair)
	}
}

func TestTLSGen_nilReceiver(t *testing.T) {
	var gen *hysteria2.TLSGen
	restore := hysteria2.SetTLSGenFactoryForTest(func() *hysteria2.TLSGen { return gen })
	defer restore()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ech.key")
	prev := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", prev) })
	binDir := t.TempDir()
	script := filepath.Join(binDir, "sing-box")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s' '"+sampleECHOutput+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Setenv("PATH", binDir+string(os.PathListSeparator)+prev)
	if _, err := hysteria2.GenerateECHKeypair("sing-box", "example.com", keyPath); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateECHKeypair_execError(t *testing.T) {
	restore := hysteria2.SetTLSGenFactoryForTest(func() *hysteria2.TLSGen {
		return &hysteria2.TLSGen{
			RunCommand: func(string, ...string) ([]byte, error) {
				return []byte("boom"), errors.New("exec failed")
			},
		}
	})
	defer restore()
	_, err := hysteria2.GenerateECHKeypair("sing-box", "example.com", filepath.Join(t.TempDir(), "k"))
	if err == nil || !strings.Contains(err.Error(), "sing-box generate ech-keypair") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGenerateECHKeypair_defaultFactory(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ech.key")
	script := filepath.Join(dir, "sing-box")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s' '"+sampleECHOutput+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	pair, err := hysteria2.GenerateECHKeypair(script, "example.com", keyPath)
	if err != nil || pair.KeyPath != keyPath {
		t.Fatalf("GenerateECHKeypair() = %#v, %v", pair, err)
	}
}

func TestGenerateECHKeypair_writeError(t *testing.T) {
	restore := hysteria2.SetTLSGenFactoryForTest(func() *hysteria2.TLSGen {
		return &hysteria2.TLSGen{
			RunCommand: func(string, ...string) ([]byte, error) {
				return []byte(sampleECHOutput), nil
			},
			WriteFile: func(string, []byte, os.FileMode) error {
				return errors.New("write failed")
			},
		}
	})
	defer restore()
	_, err := hysteria2.GenerateECHKeypair("sing-box", "example.com", filepath.Join(t.TempDir(), "k"))
	if err == nil || !strings.Contains(err.Error(), "write ech keypair") {
		t.Fatalf("unexpected error: %v", err)
	}
}
