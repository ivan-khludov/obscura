package inbound_test

import (
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol/inbound"
)

func TestRenderFallback(t *testing.T) {
	fb, alpn := inbound.RenderFallback("127.0.0.1", 8443, map[string]inbound.FallbackTarget{
		"h2": {Server: "1.1.1.1", ServerPort: 443},
	})
	if fb["server"] != "127.0.0.1" || fb["server_port"] != 8443 {
		t.Fatalf("fallback = %#v", fb)
	}
	if alpn["h2"].(map[string]any)["server"] != "1.1.1.1" {
		t.Fatalf("alpn = %#v", alpn)
	}
}

func TestRenderFallback_empty(t *testing.T) {
	fb, alpn := inbound.RenderFallback("", 0, nil)
	if fb != nil || alpn != nil {
		t.Fatalf("fb=%#v alpn=%#v", fb, alpn)
	}
}
