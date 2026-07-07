package runtime_test

import (
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/runtime"
)

func TestNewProtocolRegistry(t *testing.T) {
	reg := runtime.NewProtocolRegistry()
	got := reg.List()
	want := protocol.DisplayOrder
	if len(got) != len(want) {
		t.Fatalf("registry list length = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("registry protocol[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
