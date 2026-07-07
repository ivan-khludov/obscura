package wireguard_test

import (
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol/wireguard"
)

func TestGenerateKeypair(t *testing.T) {
	pair, err := wireguard.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := wireguard.ValidateKey(pair.PrivateKey); err != nil {
		t.Fatalf("private key: %v", err)
	}
	if err := wireguard.ValidateKey(pair.PublicKey); err != nil {
		t.Fatalf("public key: %v", err)
	}
	pub, err := wireguard.PublicKeyFromPrivate(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if pub != pair.PublicKey {
		t.Fatalf("derived public key mismatch: %q != %q", pub, pair.PublicKey)
	}
}

func TestKeyGen_GenerateKeypair_error(t *testing.T) {
	gen := &wireguard.KeyGen{RandRead: errReader{}}
	_, err := gen.GenerateKeypair()
	if err == nil || !strings.Contains(err.Error(), "generate private key") {
		t.Fatalf("expected generate error, got %v", err)
	}
}

func TestKeyGen_randReader_usesInjected(t *testing.T) {
	called := false
	gen := &wireguard.KeyGen{RandRead: readerFunc(func(p []byte) (int, error) {
		called = true
		for i := range p {
			p[i] = byte(i + 1)
		}
		return len(p), nil
	})}
	pair, err := gen.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("expected injected reader to be used")
	}
	if pair.PrivateKey == "" || pair.PublicKey == "" {
		t.Fatal("expected keypair")
	}
}

func TestKeyGen_nilReceiver(t *testing.T) {
	var gen *wireguard.KeyGen
	if _, err := gen.GenerateKeypair(); err != nil {
		t.Fatal(err)
	}
}

func TestPublicKeyFromPrivate_errors(t *testing.T) {
	if _, err := wireguard.PublicKeyFromPrivate("not-base64!!!"); err == nil || !strings.Contains(err.Error(), "decode private key") {
		t.Fatalf("expected decode error, got %v", err)
	}
	if _, err := wireguard.PublicKeyFromPrivate("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="); err == nil || !strings.Contains(err.Error(), "invalid private key") {
		t.Fatalf("expected invalid private key error, got %v", err)
	}
}
