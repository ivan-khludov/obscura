package tuic

import (
	"os"

	"github.com/ivan-khludov/obscura/internal/protocol/ech"
)

// ECHKeypair holds a sing-box ECH keypair output paths.
type ECHKeypair struct {
	KeyPath string
}

// TLSGen generates TLS ECH key material with optional dependency injection.
type TLSGen struct {
	RunCommand func(name string, args ...string) ([]byte, error)
	WriteFile  func(name string, data []byte, perm os.FileMode) error
}

var newTLSGen = func() *TLSGen { return &TLSGen{} }

func (g *TLSGen) keygen() *ech.Keygen {
	kg := &ech.Keygen{}
	if g != nil {
		kg.RunCommand = g.RunCommand
		kg.WriteFile = g.WriteFile
	}
	return kg
}

// GenerateECHKeypair runs sing-box generate ech-keypair and writes the key to keyPath.
func (g *TLSGen) GenerateECHKeypair(singBoxPath, serverName, keyPath string) (ECHKeypair, error) {
	if err := g.keygen().GenerateKeypair(singBoxPath, serverName, keyPath); err != nil {
		return ECHKeypair{}, err
	}
	return ECHKeypair{KeyPath: keyPath}, nil
}

// GenerateECHKeypair runs sing-box generate ech-keypair and writes the key to keyPath.
func GenerateECHKeypair(singBoxPath, serverName, keyPath string) (ECHKeypair, error) {
	return newTLSGen().GenerateECHKeypair(singBoxPath, serverName, keyPath)
}
