package tuic_test

import (
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol/tuic"
)

func TestRenderTLS(t *testing.T) {
	tls := tuic.RenderTLSForTest(tuic.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com", ALPN: []string{"h3"},
	})
	if tls["server_name"] != "example.com" {
		t.Fatalf("tls = %#v", tls)
	}
}

func TestApplyQUICFields(t *testing.T) {
	target := map[string]any{}
	tuic.ApplyQUICFieldsForTest(target, tuic.ProtocolData{
		InitialPacketSize: 1200, DisablePathMTUDiscovery: true,
		HTTP2: &tuic.HTTP2Options{IdleTimeout: "30s"},
	})
	if target["initial_packet_size"] != 1200 || target["disable_path_mtu_discovery"] != true {
		t.Fatalf("quic = %#v", target)
	}
}

func TestUsersFromClientsForTest(t *testing.T) {
	users := tuic.UsersFromClientsForTest(nil)
	if users == nil {
		t.Fatal("expected non-nil empty slice")
	}
}
