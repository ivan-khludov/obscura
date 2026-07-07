package domain_test

import (
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
)

func TestDefaultListenOptions(t *testing.T) {
	opts := domain.DefaultListenOptions()
	if opts.Listen != "0.0.0.0" {
		t.Fatalf("Listen = %q, want 0.0.0.0", opts.Listen)
	}
	if opts.ListenPort != 1080 {
		t.Fatalf("ListenPort = %d, want 1080", opts.ListenPort)
	}
}
