package vmess

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/ivan-khludov/obscura/internal/protocol/ech"
)

var tlsGenFactory = func() *TLSGen { return &TLSGen{} }

// TLSGen generates Reality/ECH TLS material with optional dependency injection.
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

func (g *TLSGen) randReader() io.Reader {
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
	return (&TLSGen{}).GenerateRealityKeypair(singBoxPath)
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

// GenerateRealityShortID creates a random hex short_id (up to 8 digits).
func GenerateRealityShortID() (string, error) {
	return (&TLSGen{}).GenerateRealityShortID()
}

// GenerateRealityShortID creates a random hex short_id (up to 8 digits).
func (g *TLSGen) GenerateRealityShortID() (string, error) {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(g.randReader(), buf); err != nil {
		return "", fmt.Errorf("generate reality short_id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// GenerateECHKeypair runs sing-box generate ech-keypair and writes the key to keyPath.
func GenerateECHKeypair(singBoxPath, serverName, keyPath string) (ECHKeypair, error) {
	return (&TLSGen{}).GenerateECHKeypair(singBoxPath, serverName, keyPath)
}

// GenerateECHKeypair runs sing-box generate ech-keypair and writes the key to keyPath.
func (g *TLSGen) GenerateECHKeypair(singBoxPath, serverName, keyPath string) (ECHKeypair, error) {
	k := &ech.Keygen{}
	if g != nil && g.RunCommand != nil {
		k.RunCommand = g.RunCommand
	}
	if err := k.GenerateKeypair(singBoxPath, serverName, keyPath); err != nil {
		return ECHKeypair{}, err
	}
	return ECHKeypair{KeyPath: keyPath}, nil
}
