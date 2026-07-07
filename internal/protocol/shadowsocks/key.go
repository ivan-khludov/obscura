package shadowsocks

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// DefaultMethod is the default SS-2022 cipher for new VPNs.
const DefaultMethod = "2022-blake3-aes-128-gcm"

// Methods lists SS-2022 ciphers available for multi-user VPNs in obscura.
// Sing-box supports EIH multi-user only for AES-based 2022 methods, not chacha20.
var Methods = []string{
	DefaultMethod,
	"2022-blake3-aes-256-gcm",
}

// SupportsMultiUser reports whether sing-box supports SS-2022 EIH multi-user for method.
func SupportsMultiUser(method string) bool {
	switch method {
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		return true
	default:
		return false
	}
}

// KeyLength returns the required raw key length in bytes for a cipher method.
func KeyLength(method string) (int, error) {
	switch method {
	case "2022-blake3-aes-128-gcm":
		return 16, nil
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		return 32, nil
	default:
		return 0, fmt.Errorf("unsupported shadowsocks method %q", method)
	}
}

// IsSupportedMethod reports whether method can be used for obscura multi-user VPNs.
func IsSupportedMethod(method string) bool {
	return SupportsMultiUser(method)
}

// KeyGen generates Shadowsocks keys with optional dependency injection.
type KeyGen struct {
	RandRead io.Reader
}

func (g *KeyGen) randReader() io.Reader {
	if g != nil && g.RandRead != nil {
		return g.RandRead
	}
	return rand.Reader
}

// GenerateKey creates a random base64-encoded key for the given method.
func GenerateKey(method string) (string, error) {
	return (&KeyGen{}).GenerateKey(method)
}

// GenerateKey creates a random base64-encoded key for the given method.
func (g *KeyGen) GenerateKey(method string) (string, error) {
	n, err := KeyLength(method)
	if err != nil {
		return "", err
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(g.randReader(), buf); err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

// ValidateKey checks that key is valid base64 with the expected length for method.
func ValidateKey(method, key string) error {
	n, err := KeyLength(method)
	if err != nil {
		return err
	}
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return fmt.Errorf("invalid base64 key: %w", err)
	}
	if len(raw) != n {
		return fmt.Errorf("key length must be %d bytes for %s, got %d", n, method, len(raw))
	}
	return nil
}
