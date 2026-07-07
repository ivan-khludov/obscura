// Package ech generates TLS ECH key material via sing-box.
package ech

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

var pemEncode = pem.Encode

// Keygen generates ECH keypairs with optional dependency injection.
type Keygen struct {
	RunCommand func(name string, args ...string) ([]byte, error)
	WriteFile  func(name string, data []byte, perm os.FileMode) error
}

func (k *Keygen) runCommand(name string, args ...string) ([]byte, error) {
	if k != nil && k.RunCommand != nil {
		return k.RunCommand(name, args...)
	}
	return exec.Command(name, args...).CombinedOutput()
}

func (k *Keygen) writeFile(name string, data []byte, perm os.FileMode) error {
	if k != nil && k.WriteFile != nil {
		return k.WriteFile(name, data, perm)
	}
	return os.WriteFile(name, data, perm)
}

// GenerateKeypair runs sing-box generate ech-keypair and writes the ECH KEYS PEM block to keyPath.
func GenerateKeypair(singBoxPath, serverName, keyPath string) error {
	return (&Keygen{}).GenerateKeypair(singBoxPath, serverName, keyPath)
}

// GenerateKeypair runs sing-box generate ech-keypair and writes the ECH KEYS PEM block to keyPath.
func (k *Keygen) GenerateKeypair(singBoxPath, serverName, keyPath string) error {
	if singBoxPath == "" {
		singBoxPath = "sing-box"
	}
	if serverName == "" {
		serverName = "localhost"
	}
	out, err := k.runCommand(singBoxPath, "generate", "ech-keypair", serverName)
	if err != nil {
		return fmt.Errorf("sing-box generate ech-keypair: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if keyPath == "" {
		return fmt.Errorf("ech key path is required")
	}
	keysPEM, err := extractECHKeysPEM(out)
	if err != nil {
		return err
	}
	if err := k.writeFile(keyPath, keysPEM, 0o600); err != nil {
		return fmt.Errorf("write ech keypair: %w", err)
	}
	return nil
}

func extractECHKeysPEM(output []byte) ([]byte, error) {
	rest := output
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "ECH KEYS" {
			var buf bytes.Buffer
			if err := pemEncode(&buf, block); err != nil {
				return nil, fmt.Errorf("encode ECH KEYS pem: %w", err)
			}
			return buf.Bytes(), nil
		}
		rest = remaining
	}
	return nil, fmt.Errorf("ECH KEYS block not found in sing-box output")
}

// ExtractECHKeysPEMForTest exposes extractECHKeysPEM for tests.
func ExtractECHKeysPEMForTest(output []byte) ([]byte, error) {
	return extractECHKeysPEM(output)
}
