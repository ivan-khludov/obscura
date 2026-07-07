package inbound_test

import (
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol/inbound"
)

func TestRenderTLSCore(t *testing.T) {
	got := inbound.RenderTLSCore(inbound.TLSCoreParams{
		ServerName:                       "example.com",
		ALPN:                             []string{"h2", "http/1.1"},
		MinVersion:                       "1.2",
		MaxVersion:                       "1.3",
		CipherSuites:                     []string{"TLS_AES_128_GCM_SHA256"},
		CurvePreferences:                 []string{"X25519"},
		ClientAuthentication:             "require",
		ClientCertificatePaths:           []string{"/c.pem"},
		ClientCertificatePublicKeySHA256: []string{"abc"},
		KernelTX:                         true,
		KernelRX:                         true,
		HandshakeTimeout:                 "10s",
		CertPath:                         "/cert.pem",
		KeyPath:                          "/key.pem",
		ACME:                             &inbound.ACMEOptions{Domains: []string{"example.com"}, Email: "a@b.com"},
		ECHEnabled:                       true,
		ECHKeyPath:                       "/ech.pem",
		RealityEnabled:                   true,
		RealityHandshakeServer:           "front.com",
		Reality: &inbound.RealityParams{
			PrivateKey: "pk", ShortIDs: []string{"id"}, HandshakeServer: "front.com", HandshakePort: 443,
		},
	})
	if got["server_name"] != "front.com" || got["kernel_tx"] != true {
		t.Fatalf("got %#v", got)
	}
	if got["acme"] == nil || got["ech"] == nil || got["reality"] == nil {
		t.Fatalf("missing nested tls fields: %#v", got)
	}
}

func TestRenderTLSCore_minimal(t *testing.T) {
	got := inbound.RenderTLSCore(inbound.TLSCoreParams{})
	if got["enabled"] != true {
		t.Fatalf("got %#v", got)
	}
}
