package inbound_test

import (
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol/inbound"
)

func TestRenderMultiplex(t *testing.T) {
	got := inbound.RenderMultiplex(true, true, 100, 200)
	if got["enabled"] != true || got["padding"] != true {
		t.Fatalf("got %#v", got)
	}
	brutal := got["brutal"].(map[string]any)
	if brutal["up_mbps"] != 100 || brutal["down_mbps"] != 200 {
		t.Fatalf("brutal = %#v", brutal)
	}
}

func TestRenderMultiplex_minimal(t *testing.T) {
	got := inbound.RenderMultiplex(false, false, 0, 0)
	if got["enabled"] != true {
		t.Fatalf("got %#v", got)
	}
	if _, ok := got["brutal"]; ok {
		t.Fatal("unexpected brutal")
	}
}
