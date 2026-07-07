package trojan_test

import (
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/trojan"
)

func TestParseProtocolData(t *testing.T) {
	empty, err := trojan.ParseProtocolData(nil)
	if err != nil || empty.ServerName != "" {
		t.Fatalf("empty parse: %#v, %v", empty, err)
	}
	got, err := trojan.ParseProtocolData([]byte(`{"server_name":"example.com"}`))
	if err != nil || got.ServerName != "example.com" {
		t.Fatalf("parse: %#v, %v", got, err)
	}
	_, err = trojan.ParseProtocolData([]byte(`{`))
	if err == nil || !strings.Contains(err.Error(), "parse trojan protocol data") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestMarshalProtocolData(t *testing.T) {
	raw, err := trojan.MarshalProtocolData(trojan.ProtocolData{
		ServerName: "example.com",
		CertPath:   "/a.crt",
		KeyPath:    "/a.key",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "example.com") {
		t.Fatalf("unexpected marshal: %s", raw)
	}
}

func TestTLSMode(t *testing.T) {
	if got := trojan.TLSMode(trojan.ProtocolData{RealityEnabled: true}); got != "reality" {
		t.Fatalf("reality mode = %q", got)
	}
	if got := trojan.TLSMode(trojan.ProtocolData{
		ACME: &trojan.ACMEOptions{Domains: []string{"example.com"}},
	}); got != "acme" {
		t.Fatalf("acme mode = %q", got)
	}
	if got := trojan.TLSMode(trojan.ProtocolData{CertPath: "/a.crt"}); got != "standard" {
		t.Fatalf("standard mode = %q", got)
	}
}

func TestValidateOptions(t *testing.T) {
	validCert := trojan.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
	}
	tests := []struct {
		name    string
		data    trojan.ProtocolData
		wantErr bool
	}{
		{name: "valid standard", data: validCert},
		{
			name: "valid multiplex",
			data: trojan.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
				Multiplex: true, MultiplexPadding: true,
			},
		},
		{
			name: "valid ws transport",
			data: trojan.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
				TransportType: "ws", TransportWS: &trojan.TransportWS{Path: "/x"},
			},
		},
		{
			name: "valid acme",
			data: trojan.ProtocolData{
				ServerName: "example.com",
				ACME:       &trojan.ACMEOptions{Domains: []string{"example.com"}, Email: "a@b.c"},
			},
		},
		{
			name: "valid reality",
			data: trojan.ProtocolData{
				RealityEnabled: true, RealityPrivateKey: "key", RealityShortIDs: []string{"abcd"},
				RealityHandshakeServer: "www.bing.com",
			},
		},
		{name: "missing tls", data: trojan.ProtocolData{ServerName: "example.com"}, wantErr: true},
		{
			name: "conflicting tls modes",
			data: trojan.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", RealityEnabled: true,
				RealityPrivateKey: "k", RealityShortIDs: []string{"ab"},
				RealityHandshakeServer: "x.com",
			},
			wantErr: true,
		},
		{
			name: "fallback port without server",
			data: trojan.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", FallbackPort: 8080,
			},
			wantErr: true,
		},
		{
			name:    "cert path only",
			data:    trojan.ProtocolData{CertPath: "/a.crt", ServerName: "example.com"},
			wantErr: true,
		},
		{
			name: "invalid transport",
			data: trojan.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", TransportType: "bad",
			},
			wantErr: true,
		},
		{
			name: "ech without key path",
			data: trojan.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", ECHEnabled: true,
			},
			wantErr: true,
		},
		{
			name: "acme missing email",
			data: trojan.ProtocolData{
				ACME: &trojan.ACMEOptions{Domains: []string{"example.com"}},
			},
			wantErr: true,
		},
		{
			name: "reality missing private key",
			data: trojan.ProtocolData{
				RealityEnabled: true, RealityShortIDs: []string{"ab"}, RealityHandshakeServer: "x.com",
			},
			wantErr: true,
		},
		{
			name: "reality missing short id",
			data: trojan.ProtocolData{
				RealityEnabled: true, RealityPrivateKey: "k", RealityHandshakeServer: "x.com",
			},
			wantErr: true,
		},
		{
			name: "reality missing handshake server",
			data: trojan.ProtocolData{
				RealityEnabled: true, RealityPrivateKey: "k", RealityShortIDs: []string{"ab"},
			},
			wantErr: true,
		},
		{
			name: "ws transport missing settings",
			data: trojan.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", TransportType: "ws",
			},
			wantErr: true,
		},
		{
			name:    "key path only",
			data:    trojan.ProtocolData{KeyPath: "/a.key", ServerName: "example.com"},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := trojan.ValidateOptions(tc.data)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateOptions() err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestDefaultALPN(t *testing.T) {
	if len(trojan.DefaultALPN) == 0 {
		t.Fatal("expected default alpn")
	}
}

func TestTransportModes(t *testing.T) {
	if len(trojan.TransportModes) == 0 {
		t.Fatal("expected transport modes")
	}
}

func TestUsersFromClients(t *testing.T) {
	users := trojan.UsersFromClients([]domain.ClientConfig{
		{Name: "enabled", Password: "p", Enabled: true},
		{Name: "disabled", Password: "p", Enabled: false},
		{Username: "user", Password: "p2", Enabled: true},
	})
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
	if users[0]["name"] != "enabled" || users[1]["name"] != "user" {
		t.Fatalf("unexpected users: %#v", users)
	}
}
