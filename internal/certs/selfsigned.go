package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Generator creates self-signed TLS certificates with injectable dependencies.
type Generator struct {
	fs          FileSystem
	generateKey func(io.Reader) (*ecdsa.PrivateKey, error)
	randSerial  func(io.Reader, *big.Int) (*big.Int, error)
	createCert  func(io.Reader, *x509.Certificate, *x509.Certificate, any, any) ([]byte, error)
	marshalKey  func(*ecdsa.PrivateKey) ([]byte, error)
}

func newGenerator(fs FileSystem) *Generator {
	return &Generator{
		fs: fs,
		generateKey: func(r io.Reader) (*ecdsa.PrivateKey, error) {
			return ecdsa.GenerateKey(elliptic.P256(), r)
		},
		randSerial: rand.Int,
		createCert: x509.CreateCertificate,
		marshalKey: x509.MarshalECPrivateKey,
	}
}

// GenerateSelfSigned creates a self-signed TLS certificate and private key.
func GenerateSelfSigned(host, certPath, keyPath string) error {
	return newGenerator(NewOSFileSystem()).generate(host, certPath, keyPath)
}

func (g *Generator) generate(host, certPath, keyPath string) (err error) {
	if host == "" {
		host = "localhost"
	}
	if err := g.fs.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return fmt.Errorf("create cert dir: %w", err)
	}

	privateKey, err := g.generateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	serial, err := g.randSerial(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}

	dnsNames := []string{host}
	if host != "localhost" && host != "127.0.0.1" {
		dnsNames = append(dnsNames, "localhost")
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	}
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"))

	der, err := g.createCert(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	certOut, err := g.fs.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	defer func() {
		if cerr := certOut.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close cert: %w", cerr)
		}
	}()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return fmt.Errorf("encode cert: %w", err)
	}

	keyDER, err := g.marshalKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	keyOut, err := g.fs.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	defer func() {
		if cerr := keyOut.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close key: %w", cerr)
		}
	}()
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return fmt.Errorf("encode key: %w", err)
	}
	return nil
}
