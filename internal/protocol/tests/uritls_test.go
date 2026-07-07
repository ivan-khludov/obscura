package protocol_test

import (
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol"
)

func TestShareLinkInsecureTLS(t *testing.T) {
	if !protocol.ShareLinkInsecureTLS("standard") {
		t.Fatal("expected standard TLS to need insecure share link")
	}
	for _, mode := range []string{"", "none", "acme", "reality"} {
		if protocol.ShareLinkInsecureTLS(mode) {
			t.Fatalf("mode %q should not need insecure share link", mode)
		}
	}
}

func TestDefaultRealityShareLinkFingerprint(t *testing.T) {
	if protocol.DefaultRealityShareLinkFingerprint == "" {
		t.Fatal("expected default fingerprint")
	}
}
