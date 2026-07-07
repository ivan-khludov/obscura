package listen_test

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/listen"
)

func validListen() domain.ListenOptions {
	return domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443}
}

func TestValidateListen_ok(t *testing.T) {
	if err := listen.ValidateListen(validListen()); err != nil {
		t.Fatal(err)
	}
	if err := listen.ValidateListen(domain.ListenOptions{Listen: "::", ListenPort: 80}); err != nil {
		t.Fatal(err)
	}
	if err := listen.ValidateListen(domain.ListenOptions{Listen: "127.0.0.1", ListenPort: 80}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateListen_hostnameResolves(t *testing.T) {
	if err := listen.ValidateListen(domain.ListenOptions{Listen: "localhost", ListenPort: 443}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateListen_errors(t *testing.T) {
	if err := listen.ValidateListen(domain.ListenOptions{ListenPort: 443}); err == nil {
		t.Fatal("expected missing listen error")
	}
	if err := listen.ValidateListen(domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 0}); err == nil {
		t.Fatal("expected port error")
	}
}

func TestValidator_ValidateListen_resolveError(t *testing.T) {
	v := &listen.Validator{
		ResolveIP: func(string, string) (*net.IPAddr, error) {
			return nil, errors.New("dns failed")
		},
	}
	err := v.ValidateListen(domain.ListenOptions{Listen: "host.example.com", ListenPort: 443})
	if err == nil || !strings.Contains(err.Error(), "invalid listen address") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidator_ValidateListen_resolveOk(t *testing.T) {
	v := &listen.Validator{
		ResolveIP: func(string, string) (*net.IPAddr, error) {
			return &net.IPAddr{IP: net.ParseIP("1.2.3.4")}, nil
		},
	}
	if err := v.ValidateListen(domain.ListenOptions{Listen: "host.example.com", ListenPort: 443}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRoutingMark(t *testing.T) {
	if err := listen.ValidateRoutingMark(""); err != nil {
		t.Fatal(err)
	}
	if err := listen.ValidateRoutingMark("100"); err != nil {
		t.Fatal(err)
	}
	if err := listen.ValidateRoutingMark("0x10"); err != nil {
		t.Fatal(err)
	}
	if err := listen.ValidateRoutingMark("bad"); err == nil {
		t.Fatal("expected error")
	}
}

func TestApplyOptionalFields(t *testing.T) {
	inbound := map[string]any{}
	listen.ApplyOptionalFields(inbound, domain.ListenOptions{
		BindInterface: "eth0", RoutingMark: "100", ReuseAddr: true, Netns: "ns",
		TCPFastOpen: true, TCPMultiPath: true, DisableTCPKeepAlive: true,
		TCPKeepAlive: "30s", TCPKeepAliveInterval: "10s", UDPFragment: true,
		UDPTimeout: "60s", Detour: "d",
	})
	if inbound["bind_interface"] != "eth0" || inbound["routing_mark"] != uint64(100) {
		t.Fatalf("got %#v", inbound)
	}
}

func TestApplyOptionalFields_hexRoutingMark(t *testing.T) {
	inbound := map[string]any{}
	listen.ApplyOptionalFields(inbound, domain.ListenOptions{RoutingMark: "0x10"})
	if inbound["routing_mark"] != uint64(16) {
		t.Fatalf("got %#v", inbound)
	}
}

func TestApplyOptionalFields_invalidRoutingMarkPassthrough(t *testing.T) {
	inbound := map[string]any{}
	listen.ApplyOptionalFields(inbound, domain.ListenOptions{RoutingMark: "0xZZ"})
	if inbound["routing_mark"] != "0xZZ" {
		t.Fatalf("got %#v", inbound)
	}
}

func TestUsersFromClients(t *testing.T) {
	users := listen.UsersFromClients([]domain.ClientConfig{
		{Username: "a", Password: "p", Enabled: true},
		{Username: "b", Password: "p2", Enabled: false},
	})
	if len(users) != 1 || users[0]["username"] != "a" {
		t.Fatalf("got %#v", users)
	}
}

func TestProxyHost(t *testing.T) {
	vpn := domain.VPNConfig{
		ClientHost: "vpn.example.com",
		Listen:     domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
	}
	if got := listen.ProxyHost(vpn, "hostname.local"); got != "vpn.example.com" {
		t.Fatalf("ProxyHost() = %q, want vpn.example.com", got)
	}
	vpn.ClientHost = ""
	if got := listen.ProxyHost(vpn, "hostname.local"); got != "hostname.local" {
		t.Fatalf("ProxyHost() = %q, want hostname.local", got)
	}
	if got := listen.ProxyHost(vpn, ""); got != "127.0.0.1" {
		t.Fatalf("ProxyHost() = %q, want 127.0.0.1", got)
	}
}

func TestApplyOptionalFields_decimalInvalidPassthrough(t *testing.T) {
	inbound := map[string]any{}
	listen.ApplyOptionalFields(inbound, domain.ListenOptions{RoutingMark: "not-a-number"})
	if inbound["routing_mark"] != "not-a-number" {
		t.Fatalf("got %#v", inbound)
	}
}
