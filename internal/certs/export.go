package certs

import (
	"crypto/ecdsa"
	"crypto/x509"
	"io"
	"math/big"
)

// GeneratorOption configures a Generator for tests.
type GeneratorOption func(*Generator)

// WithGenerateKey sets the key generation function.
func WithGenerateKey(fn func(io.Reader) (*ecdsa.PrivateKey, error)) GeneratorOption {
	return func(g *Generator) {
		g.generateKey = fn
	}
}

// WithRandSerial sets the serial number generation function.
func WithRandSerial(fn func(io.Reader, *big.Int) (*big.Int, error)) GeneratorOption {
	return func(g *Generator) {
		g.randSerial = fn
	}
}

// WithCreateCert sets the certificate creation function.
func WithCreateCert(fn func(io.Reader, *x509.Certificate, *x509.Certificate, any, any) ([]byte, error)) GeneratorOption {
	return func(g *Generator) {
		g.createCert = fn
	}
}

// WithMarshalKey sets the private key marshaling function.
func WithMarshalKey(fn func(*ecdsa.PrivateKey) ([]byte, error)) GeneratorOption {
	return func(g *Generator) {
		g.marshalKey = fn
	}
}

// NewGeneratorForTest returns a Generator with the given filesystem and options.
func NewGeneratorForTest(fs FileSystem, opts ...GeneratorOption) *Generator {
	g := newGenerator(fs)
	for _, opt := range opts {
		opt(g)
	}
	return g
}

// GenerateForTest runs certificate generation for external tests.
func (g *Generator) GenerateForTest(host, certPath, keyPath string) error {
	return g.generate(host, certPath, keyPath)
}
