package certs_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/certs"
)

func assertGeneratedCert(t *testing.T, certPath, keyPath string) {
	t.Helper()
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("expected PEM certificate")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("invalid certificate: %v", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("expected PEM private key")
	}
	if _, err := x509.ParseECPrivateKey(keyBlock.Bytes); err != nil {
		t.Fatalf("invalid private key: %v", err)
	}
}

func TestGenerateSelfSigned(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "test.crt")
	keyPath := filepath.Join(dir, "test.key")
	if err := certs.GenerateSelfSigned("example.com", certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	assertGeneratedCert(t, certPath, keyPath)
}

func TestGenerateSelfSigned_emptyHost(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "test.crt")
	keyPath := filepath.Join(dir, "test.key")
	if err := certs.GenerateSelfSigned("", certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	assertGeneratedCert(t, certPath, keyPath)
}

func TestGenerateSelfSigned_localhostHost(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "test.crt")
	keyPath := filepath.Join(dir, "test.key")
	if err := certs.GenerateSelfSigned("localhost", certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	assertGeneratedCert(t, certPath, keyPath)
}

func TestGenerateSelfSigned_loopbackIPHost(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "test.crt")
	keyPath := filepath.Join(dir, "test.key")
	if err := certs.GenerateSelfSigned("127.0.0.1", certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	assertGeneratedCert(t, certPath, keyPath)
}

func TestGenerateSelfSigned_ipHost(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "test.crt")
	keyPath := filepath.Join(dir, "test.key")
	if err := certs.GenerateSelfSigned("10.0.0.1", certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	assertGeneratedCert(t, certPath, keyPath)
}

func TestGenerateSelfSigned_mkdirError(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(blocker, "nested", "test.crt")
	keyPath := filepath.Join(dir, "test.key")
	err := certs.GenerateSelfSigned("example.com", certPath, keyPath)
	if err == nil || !strings.Contains(err.Error(), "create cert dir") {
		t.Fatalf("GenerateSelfSigned() = %v, want create cert dir error", err)
	}
}

func TestGenerateSelfSigned_certOpenError(t *testing.T) {
	dir := t.TempDir()
	certPath := dir
	keyPath := filepath.Join(dir, "test.key")
	err := certs.GenerateSelfSigned("example.com", certPath, keyPath)
	if err == nil || !strings.Contains(err.Error(), "write cert") {
		t.Fatalf("GenerateSelfSigned() = %v, want write cert error", err)
	}
}

func TestGenerateSelfSigned_keyOpenError(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "test.crt")
	keyPath := dir
	err := certs.GenerateSelfSigned("example.com", certPath, keyPath)
	if err == nil || !strings.Contains(err.Error(), "write key") {
		t.Fatalf("GenerateSelfSigned() = %v, want write key error", err)
	}
}

func TestGenerateSelfSigned_generateKeyError(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "test.crt")
	keyPath := filepath.Join(dir, "test.key")
	g := certs.NewGeneratorForTest(certs.NewOSFileSystem(), certs.WithGenerateKey(func(io.Reader) (*ecdsa.PrivateKey, error) {
		return nil, errors.New("key gen failed")
	}))
	err := g.GenerateForTest("example.com", certPath, keyPath)
	if err == nil || !strings.Contains(err.Error(), "generate key") {
		t.Fatalf("GenerateForTest() = %v, want generate key error", err)
	}
}

func TestGenerateSelfSigned_randSerialError(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "test.crt")
	keyPath := filepath.Join(dir, "test.key")
	g := certs.NewGeneratorForTest(certs.NewOSFileSystem(), certs.WithRandSerial(func(io.Reader, *big.Int) (*big.Int, error) {
		return nil, errors.New("serial failed")
	}))
	err := g.GenerateForTest("example.com", certPath, keyPath)
	if err == nil || !strings.Contains(err.Error(), "generate serial") {
		t.Fatalf("GenerateForTest() = %v, want generate serial error", err)
	}
}

func TestGenerateSelfSigned_createCertError(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "test.crt")
	keyPath := filepath.Join(dir, "test.key")
	g := certs.NewGeneratorForTest(certs.NewOSFileSystem(), certs.WithCreateCert(func(io.Reader, *x509.Certificate, *x509.Certificate, any, any) ([]byte, error) {
		return nil, errors.New("cert failed")
	}))
	err := g.GenerateForTest("example.com", certPath, keyPath)
	if err == nil || !strings.Contains(err.Error(), "create certificate") {
		t.Fatalf("GenerateForTest() = %v, want create certificate error", err)
	}
}

func TestGenerateSelfSigned_marshalKeyError(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "test.crt")
	keyPath := filepath.Join(dir, "test.key")
	g := certs.NewGeneratorForTest(certs.NewOSFileSystem(), certs.WithMarshalKey(func(*ecdsa.PrivateKey) ([]byte, error) {
		return nil, errors.New("marshal failed")
	}))
	err := g.GenerateForTest("example.com", certPath, keyPath)
	if err == nil || !strings.Contains(err.Error(), "marshal key") {
		t.Fatalf("GenerateForTest() = %v, want marshal key error", err)
	}
}
