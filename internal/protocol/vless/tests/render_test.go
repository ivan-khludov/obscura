package vless_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/vless"
)

func TestRenderMultiplex(t *testing.T) {
	got := vless.RenderMultiplexForTest(vless.ProtocolData{
		MultiplexPadding: true, MultiplexBrutal: true,
		MultiplexBrutalUpMbps: 10, MultiplexBrutalDownMbps: 20,
	})
	if got["enabled"] != true {
		t.Fatalf("unexpected multiplex: %#v", got)
	}
}

func TestRealityHandshakePort(t *testing.T) {
	if vless.RealityHandshakePortForTest(vless.ProtocolData{}) != vless.DefaultRealityHandshakePort {
		t.Fatal("expected default port")
	}
	if vless.RealityHandshakePortForTest(vless.ProtocolData{RealityHandshakePort: 8443}) != 8443 {
		t.Fatal("expected custom port")
	}
}

func TestUsersFromClients(t *testing.T) {
	id := uuid.NewString()
	users, err := vless.UsersFromClients(vless.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key",
	}, []domain.ClientConfig{
		{Name: "phone", Password: id, Enabled: true},
		{Name: "off", Password: uuid.NewString(), Enabled: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %#v", users)
	}
}

func TestUsersFromClients_nameFromUsername(t *testing.T) {
	id := uuid.NewString()
	users, err := vless.UsersFromClients(vless.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key",
	}, []domain.ClientConfig{
		{Username: vless.FlowVision, Password: id, Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if users[0]["name"] != vless.FlowVision {
		t.Fatalf("expected name from username flow, got %#v", users[0])
	}
}

func TestUsersFromClients_flow(t *testing.T) {
	id := uuid.NewString()
	users, err := vless.UsersFromClients(vless.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", DefaultFlow: vless.FlowVision,
	}, []domain.ClientConfig{
		{Name: "phone", Password: id, Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if users[0]["flow"] != vless.FlowVision {
		t.Fatalf("expected flow, got %#v", users[0])
	}
}

func TestUsersFromClients_errors(t *testing.T) {
	_, err := vless.UsersFromClients(vless.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", DefaultFlow: vless.FlowVision,
		TransportType: "ws", TransportWS: &vless.TransportWS{Path: "/"},
	}, []domain.ClientConfig{
		{Name: "phone", Password: uuid.NewString(), Enabled: true},
	})
	if err == nil || !strings.Contains(err.Error(), "direct transport") {
		t.Fatalf("expected flow/transport error, got %v", err)
	}
}

func TestClientFlow(t *testing.T) {
	id := uuid.NewString()
	flow, err := vless.ClientFlowForTest(vless.ProtocolData{DefaultFlow: vless.FlowVision}, domain.ClientConfig{
		Password: id, Username: vless.FlowVision,
	})
	if err != nil || flow != vless.FlowVision {
		t.Fatalf("ClientFlow() = %q, %v", flow, err)
	}
	_, err = vless.ClientFlowForTest(vless.ProtocolData{}, domain.ClientConfig{Username: "bad-flow"})
	if err == nil {
		t.Fatal("expected unsupported flow error")
	}
}
