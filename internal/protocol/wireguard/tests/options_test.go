package wireguard_test

import (
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/wireguard"
)

func TestParseProtocolData(t *testing.T) {
	data, err := wireguard.ParseProtocolData(nil)
	if err != nil || len(data.Address) != 0 || data.PrivateKey != "" {
		t.Fatalf("ParseProtocolData(nil) = %#v, %v", data, err)
	}
	priv, pub := mustKeypair(t)
	raw, err := wireguard.MarshalProtocolData(wireguard.ProtocolData{
		PrivateKey: priv,
		PublicKey:  pub,
		Address:    []string{"10.8.0.1/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := wireguard.ParseProtocolData(raw)
	if err != nil || parsed.PrivateKey != priv {
		t.Fatalf("ParseProtocolData(valid) = %#v, %v", parsed, err)
	}
	if _, err := wireguard.ParseProtocolData([]byte("{")); err == nil || !strings.Contains(err.Error(), "parse wireguard protocol data") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestMarshalProtocolData(t *testing.T) {
	priv, pub := mustKeypair(t)
	raw, err := wireguard.MarshalProtocolData(wireguard.ProtocolData{
		PrivateKey: priv,
		PublicKey:  pub,
		Address:    []string{"10.8.0.1/24"},
	})
	if err != nil || len(raw) == 0 {
		t.Fatalf("MarshalProtocolData() = %q, %v", raw, err)
	}
}

func TestValidateOptions_errors(t *testing.T) {
	priv, pub := mustKeypair(t)
	base := wireguard.ProtocolData{PrivateKey: priv, PublicKey: pub, Address: []string{"10.8.0.1/24"}}

	if err := wireguard.ValidateOptions(wireguard.ProtocolData{Address: []string{"10.8.0.1/24"}}); err == nil || !strings.Contains(err.Error(), "private_key is required") {
		t.Fatalf("missing private key: %v", err)
	}
	if err := wireguard.ValidateOptions(wireguard.ProtocolData{PrivateKey: priv}); err == nil || !strings.Contains(err.Error(), "address is required") {
		t.Fatalf("missing address: %v", err)
	}
	if err := wireguard.ValidateOptions(wireguard.ProtocolData{PrivateKey: priv, Address: []string{"not-a-cidr"}}); err == nil || !strings.Contains(err.Error(), "invalid address") {
		t.Fatalf("invalid cidr: %v", err)
	}
	if err := wireguard.ValidateOptions(wireguard.ProtocolData{PrivateKey: priv, Address: []string{"10.8.0.1/24"}, MTU: 1000}); err == nil || !strings.Contains(err.Error(), "mtu must be at least 1280") {
		t.Fatalf("mtu too small: %v", err)
	}
	if err := wireguard.ValidateOptions(wireguard.ProtocolData{PrivateKey: priv, Address: []string{"10.8.0.1/24"}, PeerReserved: []int{1, 2}}); err == nil || !strings.Contains(err.Error(), "peer_reserved must contain exactly 3 bytes") {
		t.Fatalf("peer_reserved length: %v", err)
	}
	if err := wireguard.ValidateOptions(wireguard.ProtocolData{PrivateKey: "!!!", Address: []string{"10.8.0.1/24"}}); err == nil || !strings.Contains(err.Error(), "private_key:") {
		t.Fatalf("invalid private key: %v", err)
	}
	if err := wireguard.ValidateOptions(wireguard.ProtocolData{PrivateKey: priv, PublicKey: "!!!", Address: []string{"10.8.0.1/24"}}); err == nil || !strings.Contains(err.Error(), "public_key:") {
		t.Fatalf("invalid public key: %v", err)
	}
	if err := wireguard.ValidateOptions(base); err != nil {
		t.Fatalf("valid options: %v", err)
	}
}

func TestValidateKey(t *testing.T) {
	priv, _ := mustKeypair(t)
	if err := wireguard.ValidateKey(priv); err != nil {
		t.Fatalf("valid key: %v", err)
	}
	if err := wireguard.ValidateKey("not-valid!!!"); err == nil || !strings.Contains(err.Error(), "invalid base64 key") {
		t.Fatalf("invalid base64: %v", err)
	}
	if err := wireguard.ValidateKey("YWJj"); err == nil || !strings.Contains(err.Error(), "wireguard key must be 32 bytes") {
		t.Fatalf("wrong length: %v", err)
	}
}

func TestClientAllowedIPs(t *testing.T) {
	defaults := wireguard.ClientAllowedIPs(wireguard.ProtocolData{})
	if len(defaults) != 2 || defaults[0] != "0.0.0.0/0" {
		t.Fatalf("defaults = %v", defaults)
	}
	custom := wireguard.ClientAllowedIPs(wireguard.ProtocolData{ClientAllowedIPs: []string{"10.0.0.0/8"}})
	if len(custom) != 1 || custom[0] != "10.0.0.0/8" {
		t.Fatalf("custom = %v", custom)
	}
}

func TestClientTunnelIP(t *testing.T) {
	priv, pub := mustKeypair(t)
	data := wireguard.ProtocolData{
		PrivateKey: priv,
		PublicKey:  pub,
		Address:    []string{"10.8.0.1/24"},
	}
	client := testClient(t, "phone")
	ip, err := wireguard.ClientTunnelIP(data, []domain.ClientConfig{client}, "phone")
	if err != nil || ip != "10.8.0.2/32" {
		t.Fatalf("ClientTunnelIP() = %q, %v", ip, err)
	}
	if _, err := wireguard.ClientTunnelIP(wireguard.ProtocolData{}, nil, "x"); err == nil || !strings.Contains(err.Error(), "address is required") {
		t.Fatalf("empty address: %v", err)
	}
	if _, err := wireguard.ClientTunnelIP(wireguard.ProtocolData{Address: []string{"2001:db8::1/64"}}, []domain.ClientConfig{client}, "phone"); err == nil || !strings.Contains(err.Error(), "ipv6 client allocation is not implemented") {
		t.Fatalf("ipv6: %v", err)
	}
	if _, err := wireguard.ClientTunnelIP(data, []domain.ClientConfig{client}, "missing"); err == nil || !strings.Contains(err.Error(), "not found among enabled clients") {
		t.Fatalf("not found: %v", err)
	}
}

func TestClientTunnelIP_skipsDisabledClients(t *testing.T) {
	priv, pub := mustKeypair(t)
	data := wireguard.ProtocolData{
		PrivateKey: priv,
		PublicKey:  pub,
		Address:    []string{"10.8.0.1/24"},
	}
	enabled := testClient(t, "phone")
	ip, err := wireguard.ClientTunnelIP(data, []domain.ClientConfig{
		{Name: "disabled", Enabled: false},
		enabled,
	}, "phone")
	if err != nil || ip != "10.8.0.2/32" {
		t.Fatalf("ClientTunnelIP() = %q, %v", ip, err)
	}
}

func TestClientTunnelIP_parseCIDRError(t *testing.T) {
	priv, pub := mustKeypair(t)
	data := wireguard.ProtocolData{
		PrivateKey: priv,
		PublicKey:  pub,
		Address:    []string{"not-a-cidr"},
	}
	client := testClient(t, "phone")
	_, err := wireguard.ClientTunnelIP(data, []domain.ClientConfig{client}, "phone")
	if err == nil {
		t.Fatal("expected parse cidr error")
	}
}

func TestClientTunnelIP_addressExhausted(t *testing.T) {
	priv, pub := mustKeypair(t)
	data := wireguard.ProtocolData{
		PrivateKey: priv,
		PublicKey:  pub,
		Address:    []string{"10.8.0.1/30"},
	}
	clients := []domain.ClientConfig{
		testClient(t, "a"),
		testClient(t, "b"),
		testClient(t, "c"),
	}
	_, err := wireguard.ClientTunnelIP(data, clients, "c")
	if err == nil || !strings.Contains(err.Error(), "no available address") {
		t.Fatalf("expected exhausted error, got %v", err)
	}
}
