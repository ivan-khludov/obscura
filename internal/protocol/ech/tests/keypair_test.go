package ech_test

import (
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol/ech"
)

const sampleECHOutput = `-----BEGIN ECH KEYS-----
AQIDBAUGBwg=
-----END ECH KEYS-----
`

func TestGenerateKeypair_ok(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ech.key")
	k := &ech.Keygen{
		RunCommand: func(string, ...string) ([]byte, error) {
			return []byte(sampleECHOutput), nil
		},
	}
	if err := k.GenerateKeypair("sing-box", "example.com", keyPath); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "ECH KEYS") {
		t.Fatalf("unexpected key file: %q", raw)
	}
}

func TestGenerateKeypair_defaults(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ech.key")
	k := &ech.Keygen{
		RunCommand: func(string, ...string) ([]byte, error) {
			return []byte(sampleECHOutput), nil
		},
	}
	if err := k.GenerateKeypair("", "", keyPath); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateKeypair_packageFunc(t *testing.T) {
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
	if err := ech.GenerateKeypair("sing-box", "example.com", keyPath); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateKeypair_execError(t *testing.T) {
	k := &ech.Keygen{
		RunCommand: func(string, ...string) ([]byte, error) {
			return []byte("boom"), errors.New("exec failed")
		},
	}
	err := k.GenerateKeypair("sing-box", "example.com", filepath.Join(t.TempDir(), "k"))
	if err == nil || !strings.Contains(err.Error(), "sing-box generate ech-keypair") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGenerateKeypair_missingKeyPath(t *testing.T) {
	k := &ech.Keygen{
		RunCommand: func(string, ...string) ([]byte, error) {
			return []byte(sampleECHOutput), nil
		},
	}
	if err := k.GenerateKeypair("sing-box", "example.com", ""); err == nil {
		t.Fatal("expected key path error")
	}
}

func TestGenerateKeypair_noECHBlock(t *testing.T) {
	k := &ech.Keygen{
		RunCommand: func(string, ...string) ([]byte, error) {
			return []byte("no pem here"), nil
		},
	}
	err := k.GenerateKeypair("sing-box", "example.com", filepath.Join(t.TempDir(), "k"))
	if err == nil || !strings.Contains(err.Error(), "ECH KEYS block not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGenerateKeypair_writeError(t *testing.T) {
	k := &ech.Keygen{
		RunCommand: func(string, ...string) ([]byte, error) {
			return []byte(sampleECHOutput), nil
		},
		WriteFile: func(string, []byte, os.FileMode) error {
			return errors.New("write failed")
		},
	}
	err := k.GenerateKeypair("sing-box", "example.com", filepath.Join(t.TempDir(), "k"))
	if err == nil || !strings.Contains(err.Error(), "write ech keypair") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtractECHKeysPEM(t *testing.T) {
	got, err := ech.ExtractECHKeysPEMForTest([]byte(sampleECHOutput))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "BEGIN ECH KEYS") {
		t.Fatalf("got %q", got)
	}
	_, err = ech.ExtractECHKeysPEMForTest([]byte("garbage"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestExtractECHKeysPEM_multiPEM(t *testing.T) {
	const otherPEM = `-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
-----END CERTIFICATE-----
`
	got, err := ech.ExtractECHKeysPEMForTest([]byte(otherPEM + sampleECHOutput))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "BEGIN ECH KEYS") {
		t.Fatalf("got %q", got)
	}
}

func TestGenerateKeypair_multiPEM(t *testing.T) {
	const otherPEM = `-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
-----END CERTIFICATE-----
`
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ech.key")
	k := &ech.Keygen{
		RunCommand: func(string, ...string) ([]byte, error) {
			return []byte(otherPEM + sampleECHOutput), nil
		},
	}
	if err := k.GenerateKeypair("sing-box", "example.com", keyPath); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "ECH KEYS") {
		t.Fatalf("unexpected key file: %q", raw)
	}
}

func TestExtractECHKeysPEM_encodeError(t *testing.T) {
	restore := ech.SetPemEncodeHookForTest(func(io.Writer, *pem.Block) error {
		return errors.New("encode failed")
	})
	defer restore()
	_, err := ech.ExtractECHKeysPEMForTest([]byte(sampleECHOutput))
	if err == nil || !strings.Contains(err.Error(), "encode ECH KEYS pem") {
		t.Fatalf("unexpected error: %v", err)
	}
}
