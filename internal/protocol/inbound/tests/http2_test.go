package inbound_test

import (
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol/inbound"
)

func TestApplyQUICFields(t *testing.T) {
	target := map[string]any{}
	inbound.ApplyQUICFields(target, &inbound.HTTP2Options{
		IdleTimeout:             "30s",
		KeepAlivePeriod:         "10s",
		StreamReceiveWindow:     "1MB",
		ConnectionReceiveWindow: "2MB",
		MaxConcurrentStreams:    100,
	}, 1200, true)
	if target["initial_packet_size"] != 1200 || target["idle_timeout"] != "30s" || target["max_concurrent_streams"] != 100 {
		t.Fatalf("got %#v", target)
	}
}

func TestApplyQUICFields_nilHTTP2(t *testing.T) {
	target := map[string]any{}
	inbound.ApplyQUICFields(target, nil, 0, false)
	if len(target) != 0 {
		t.Fatalf("got %#v", target)
	}
}
