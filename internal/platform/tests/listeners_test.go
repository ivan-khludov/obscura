package platform_test

import (
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/platform"
)

func TestLocalPortBound_Validation(t *testing.T) {
	if _, err := platform.LocalPortBound("icmp", 80); err == nil || !strings.Contains(err.Error(), "unsupported network") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := platform.LocalPortBound("tcp", 0); err == nil || !strings.Contains(err.Error(), "invalid port") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := platform.LocalPortBound("tcp", 70000); err == nil || !strings.Contains(err.Error(), "invalid port") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPortChecker_LocalPortBound_Validation(t *testing.T) {
	var checker platform.PortChecker
	if _, err := checker.LocalPortBound("sctp", 80); err == nil {
		t.Fatal("expected unsupported network error")
	}
	if _, err := checker.LocalPortBound("udp", -1); err == nil {
		t.Fatal("expected invalid port error")
	}
}
