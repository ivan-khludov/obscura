package socks5_test

import (
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/protocol/socks5"
	"github.com/ivan-khludov/obscura/internal/protocol/testutil"
)

func TestBuildProtocolData(t *testing.T) {
	adapter := &socks5.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	raw, err := adapter.BuildProtocolData(ctx, domain.CreateVPNSpec{}, "vpn-socks", protocol.BuildModePreview)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "{}" {
		t.Fatalf("got %q", raw)
	}
}

func TestNeedsInitialClient(t *testing.T) {
	if !(&socks5.Adapter{}).NeedsInitialClient(domain.VPNConfig{}) {
		t.Fatal("expected true")
	}
}
