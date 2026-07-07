package protocol_test

import (
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol"
)

func TestValidateRealityUTLSFingerprint(t *testing.T) {
	if err := protocol.ValidateRealityUTLSFingerprint("chrome"); err != nil {
		t.Fatal(err)
	}
	if err := protocol.ValidateRealityUTLSFingerprint(""); err != nil {
		t.Fatal("empty fingerprint should be valid")
	}
	if err := protocol.ValidateRealityUTLSFingerprint("invalid"); err == nil {
		t.Fatal("expected error for invalid fingerprint")
	}
}

func TestResolveRealityUTLSFingerprint(t *testing.T) {
	if got := protocol.ResolveRealityUTLSFingerprint(""); got != protocol.DefaultRealityShareLinkFingerprint {
		t.Fatalf("got %q want %q", got, protocol.DefaultRealityShareLinkFingerprint)
	}
	if got := protocol.ResolveRealityUTLSFingerprint("firefox"); got != "firefox" {
		t.Fatalf("got %q", got)
	}
}

func TestAllowedRealityUTLSFingerprints(t *testing.T) {
	if len(protocol.AllowedRealityUTLSFingerprints) == 0 {
		t.Fatal("expected allowed fingerprints")
	}
	if err := protocol.ValidateRealityUTLSFingerprint(protocol.AllowedRealityUTLSFingerprints[0]); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRealityUTLSFingerprint_errorMessage(t *testing.T) {
	err := protocol.ValidateRealityUTLSFingerprint("bad")
	if err == nil || !strings.Contains(err.Error(), "unsupported reality fingerprint") {
		t.Fatalf("unexpected error: %v", err)
	}
}
