package inbound_test

import (
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol/inbound"
)

func validRealityParams() inbound.RealityParams {
	return inbound.RealityParams{
		PrivateKey:      "pk",
		ShortIDs:        []string{"abcd"},
		HandshakeServer: "example.com",
		HandshakePort:   443,
		UTLSFingerprint: "chrome",
	}
}

func TestRenderReality(t *testing.T) {
	got := inbound.RenderReality(inbound.RealityParams{
		PrivateKey:        "pk",
		ShortIDs:          []string{"a", "b"},
		HandshakeServer:   "example.com",
		HandshakePort:     443,
		MaxTimeDifference: "5m",
	})
	if got["private_key"] != "pk" || got["max_time_difference"] != "5m" {
		t.Fatalf("got %#v", got)
	}
}

func TestValidateReality_disabled(t *testing.T) {
	if err := inbound.ValidateReality(false, inbound.RealityParams{}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateReality_ok(t *testing.T) {
	if err := inbound.ValidateReality(true, validRealityParams()); err != nil {
		t.Fatal(err)
	}
}

func TestValidateReality_errors(t *testing.T) {
	base := validRealityParams()
	for name, mutate := range map[string]func(*inbound.RealityParams){
		"private key": func(p *inbound.RealityParams) { p.PrivateKey = "" },
		"short id":    func(p *inbound.RealityParams) { p.ShortIDs = nil },
		"handshake":   func(p *inbound.RealityParams) { p.HandshakeServer = "" },
		"fingerprint": func(p *inbound.RealityParams) { p.UTLSFingerprint = "bad" },
	} {
		p := base
		mutate(&p)
		if err := inbound.ValidateReality(true, p); err == nil {
			t.Fatalf("expected error for missing %s", name)
		}
	}
}

func TestValidateReality_fingerprintMessage(t *testing.T) {
	p := validRealityParams()
	p.UTLSFingerprint = "invalid"
	err := inbound.ValidateReality(true, p)
	if err == nil || !strings.Contains(err.Error(), "unsupported reality fingerprint") {
		t.Fatalf("unexpected error: %v", err)
	}
}
