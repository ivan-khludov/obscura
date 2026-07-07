package inbound_test

import (
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol/inbound"
)

func TestRenderACME(t *testing.T) {
	got := inbound.RenderACME(inbound.ACMEOptions{
		Domains:                 []string{"example.com"},
		DataDirectory:           "/data",
		DefaultServerName:       "example.com",
		Email:                   "a@b.com",
		Provider:                "letsencrypt",
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: true,
		AlternativeHTTPPort:     8080,
		AlternativeTLSPort:      8443,
	})
	if got["domain"] == nil || got["email"] != "a@b.com" || got["alternative_http_port"] != 8080 {
		t.Fatalf("got %#v", got)
	}
}

func TestRenderACME_minimal(t *testing.T) {
	got := inbound.RenderACME(inbound.ACMEOptions{Domains: []string{"x.com"}})
	if got["domain"] == nil {
		t.Fatalf("got %#v", got)
	}
}
