package service_test

import (
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/fallback"
	"github.com/ivan-khludov/obscura/internal/protocol/trojan"
	"github.com/ivan-khludov/obscura/internal/service"
)

func TestUsesLocalFallbackStub(t *testing.T) {
	raw, err := trojan.MarshalProtocolData(trojan.ProtocolData{
		FallbackServer: fallback.DefaultServer,
		FallbackPort:   fallback.DefaultPort,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !service.UsesLocalFallbackStubForTest(domain.VPN{Protocol: "trojan", ProtocolData: raw}) {
		t.Fatal("expected trojan fallback stub")
	}
	if service.UsesLocalFallbackStubForTest(domain.VPN{Protocol: "socks5"}) {
		t.Fatal("socks5 should not use fallback stub")
	}
	if service.UsesLocalFallbackStubForTest(domain.VPN{Protocol: "trojan", ProtocolData: []byte("bad")}) {
		t.Fatal("invalid trojan data")
	}
}
