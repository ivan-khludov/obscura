package vmess_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/vmess"
)

func TestRenderMultiplex(t *testing.T) {
	got := vmess.RenderMultiplexForTest(vmess.ProtocolData{
		MultiplexPadding: true, MultiplexBrutal: true,
		MultiplexBrutalUpMbps: 10, MultiplexBrutalDownMbps: 20,
	})
	if got["enabled"] != true {
		t.Fatalf("unexpected multiplex: %#v", got)
	}
}

func TestRealityHandshakePort(t *testing.T) {
	if vmess.RealityHandshakePortForTest(vmess.ProtocolData{}) != vmess.DefaultRealityHandshakePort {
		t.Fatal("expected default port")
	}
	if vmess.RealityHandshakePortForTest(vmess.ProtocolData{RealityHandshakePort: 8443}) != 8443 {
		t.Fatal("expected custom port")
	}
}

func TestUsersFromClients(t *testing.T) {
	id := uuid.NewString()
	users, err := vmess.UsersFromClients(vmess.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", DefaultAlterId: 0,
	}, []domain.ClientConfig{
		{Name: "phone", Password: id, Enabled: true},
		{Name: "off", Password: uuid.NewString(), Enabled: false},
		{Username: "2", Password: uuid.NewString(), Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %#v", users)
	}
	if users[1]["alterId"].(int) != 2 {
		t.Fatalf("expected alterId 2, got %#v", users[1])
	}
}

func TestUsersFromClients_nameFromUsername(t *testing.T) {
	id := uuid.NewString()
	users, err := vmess.UsersFromClients(vmess.ProtocolData{}, []domain.ClientConfig{
		{Name: "", Username: "4", Password: id, Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if users[0]["name"] != "4" {
		t.Fatalf("expected name from username, got %#v", users[0])
	}
}

func TestUsersFromClients_alterIDError(t *testing.T) {
	_, err := vmess.UsersFromClients(vmess.ProtocolData{}, []domain.ClientConfig{
		{Name: "phone", Password: uuid.NewString(), Username: "bad", Enabled: true},
	})
	if err == nil || !strings.Contains(err.Error(), "alterId must be 0-65535") {
		t.Fatalf("expected alterId error, got %v", err)
	}
}

func TestClientAlterID(t *testing.T) {
	id := uuid.NewString()
	alterID, err := vmess.ClientAlterIDForTest(vmess.ProtocolData{DefaultAlterId: 0}, domain.ClientConfig{
		Password: id, Username: "4",
	})
	if err != nil || alterID != 4 {
		t.Fatalf("ClientAlterID() = %d, %v", alterID, err)
	}
	_, err = vmess.ClientAlterIDForTest(vmess.ProtocolData{}, domain.ClientConfig{Username: "bad"})
	if err == nil || !strings.Contains(err.Error(), "alterId must be 0-65535") {
		t.Fatalf("expected alterId error, got %v", err)
	}
	_, err = vmess.ClientAlterIDForTest(vmess.ProtocolData{}, domain.ClientConfig{Username: "-1"})
	if err == nil {
		t.Fatal("expected negative alterId error")
	}
	_, err = vmess.ClientAlterIDForTest(vmess.ProtocolData{}, domain.ClientConfig{Username: "70000"})
	if err == nil {
		t.Fatal("expected out of range alterId error")
	}
}
