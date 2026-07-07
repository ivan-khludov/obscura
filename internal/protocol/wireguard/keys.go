package wireguard

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

var publicKeyFromPrivateFunc = publicKeyFromPrivate

// Keypair holds a WireGuard private/public key pair (base64).
type Keypair struct {
	PrivateKey string
	PublicKey  string
}

// KeyGen generates WireGuard keypairs with optional dependency injection.
type KeyGen struct {
	RandRead io.Reader
}

func (g *KeyGen) randReader() io.Reader {
	if g != nil && g.RandRead != nil {
		return g.RandRead
	}
	return rand.Reader
}

// GenerateKeypair creates a WireGuard keypair using Go crypto.
func GenerateKeypair() (Keypair, error) {
	return (&KeyGen{}).GenerateKeypair()
}

// GenerateKeypair creates a WireGuard keypair using Go crypto.
func (g *KeyGen) GenerateKeypair() (Keypair, error) {
	curve := ecdh.X25519()
	privateKey, err := curve.GenerateKey(g.randReader())
	if err != nil {
		return Keypair{}, fmt.Errorf("generate private key: %w", err)
	}
	return Keypair{
		PrivateKey: base64.StdEncoding.EncodeToString(privateKey.Bytes()),
		PublicKey:  base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes()),
	}, nil
}

// PublicKeyFromPrivate derives the public key from a base64 private key.
func PublicKeyFromPrivate(privateKey string) (string, error) {
	return publicKeyFromPrivateFunc(privateKey)
}

func publicKeyFromPrivate(privateKey string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("invalid private key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}
