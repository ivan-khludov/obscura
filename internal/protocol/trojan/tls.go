package trojan

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/ivan-khludov/obscura/internal/protocol/ech"
)

var newTLSGen = func() *TLSGen { return &TLSGen{} }

// TLSGen generates Trojan TLS material with optional dependency injection.
type TLSGen struct {
	RunCommand func(name string, args ...string) ([]byte, error)
	RandRead   io.Reader
}

func (g *TLSGen) runCommand(name string, args ...string) ([]byte, error) {
	if g != nil && g.RunCommand != nil {
		return g.RunCommand(name, args...)
	}
	return exec.Command(name, args...).CombinedOutput()
}

func (g *TLSGen) randRead() io.Reader {
	if g != nil && g.RandRead != nil {
		return g.RandRead
	}
	return rand.Reader
}

// RealityKeypair holds a sing-box Reality keypair.
type RealityKeypair struct {
	PrivateKey string
	PublicKey  string
}

// ECHKeypair holds a sing-box ECH keypair output paths.
type ECHKeypair struct {
	KeyPath string
}

// GenerateRealityKeypair runs sing-box generate reality-keypair.
func GenerateRealityKeypair(singBoxPath string) (RealityKeypair, error) {
	return newTLSGen().GenerateRealityKeypair(singBoxPath)
}

// GenerateRealityKeypair runs sing-box generate reality-keypair.
func (g *TLSGen) GenerateRealityKeypair(singBoxPath string) (RealityKeypair, error) {
	if singBoxPath == "" {
		singBoxPath = "sing-box"
	}
	out, err := g.runCommand(singBoxPath, "generate", "reality-keypair")
	if err != nil {
		return RealityKeypair{}, fmt.Errorf("sing-box generate reality-keypair: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return parseRealityKeypair(string(out))
}

// ParseRealityKeypairOutput parses sing-box generate reality-keypair output.
func ParseRealityKeypairOutput(output string) (RealityKeypair, error) {
	return parseRealityKeypair(output)
}

// parseRealityKeypair parses protocol or configuration data.
func parseRealityKeypair(output string) (RealityKeypair, error) {
	var pair RealityKeypair
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "PrivateKey:"):
			pair.PrivateKey = strings.TrimSpace(strings.TrimPrefix(line, "PrivateKey:"))
		case strings.HasPrefix(line, "PublicKey:"):
			pair.PublicKey = strings.TrimSpace(strings.TrimPrefix(line, "PublicKey:"))
		case strings.HasPrefix(line, "Private key:"):
			pair.PrivateKey = strings.TrimSpace(strings.TrimPrefix(line, "Private key:"))
		case strings.HasPrefix(line, "Public key:"):
			pair.PublicKey = strings.TrimSpace(strings.TrimPrefix(line, "Public key:"))
		}
	}
	if pair.PrivateKey == "" {
		var parsed map[string]string
		if err := json.Unmarshal([]byte(output), &parsed); err == nil {
			pair.PrivateKey = parsed["private_key"]
			pair.PublicKey = parsed["public_key"]
		}
	}
	if pair.PrivateKey == "" {
		return RealityKeypair{}, fmt.Errorf("parse reality keypair output: %q", output)
	}
	return pair, nil
}

// RealityPublicKeyFromPrivate derives the Reality public key from a sing-box private key.
func RealityPublicKeyFromPrivate(privateKey string) (string, error) {
	raw, err := decodeRealityKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("decode reality private key: %w", err)
	}
	priv, err := newRealityPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("invalid reality private key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

var newRealityPrivateKey = func(raw []byte) (*ecdh.PrivateKey, error) {
	return ecdh.X25519().NewPrivateKey(raw)
}

// decodeRealityKey decodes a sing-box Reality key (base64url or standard base64).
func decodeRealityKey(key string) ([]byte, error) {
	for _, dec := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.StdEncoding,
		base64.RawStdEncoding,
	} {
		raw, err := dec.DecodeString(key)
		if err == nil && len(raw) == 32 {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("invalid base64 reality key %q", key)
}

// GenerateRealityShortID creates a random hex short_id (up to 8 digits).
func GenerateRealityShortID() (string, error) {
	return newTLSGen().GenerateRealityShortID()
}

// GenerateRealityShortID creates a random hex short_id (up to 8 digits).
func (g *TLSGen) GenerateRealityShortID() (string, error) {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(g.randRead(), buf); err != nil {
		return "", fmt.Errorf("generate reality short_id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// GenerateECHKeypair runs sing-box generate ech-keypair and writes the key to keyPath.
func GenerateECHKeypair(singBoxPath, serverName, keyPath string) (ECHKeypair, error) {
	return newTLSGen().GenerateECHKeypair(singBoxPath, serverName, keyPath)
}

// GenerateECHKeypair runs sing-box generate ech-keypair and writes the key to keyPath.
func (g *TLSGen) GenerateECHKeypair(singBoxPath, serverName, keyPath string) (ECHKeypair, error) {
	kg := &ech.Keygen{RunCommand: g.RunCommand}
	if err := kg.GenerateKeypair(singBoxPath, serverName, keyPath); err != nil {
		return ECHKeypair{}, err
	}
	return ECHKeypair{KeyPath: keyPath}, nil
}
