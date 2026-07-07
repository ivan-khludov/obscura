package hysteria2_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol/hysteria2"
)

func validCert() hysteria2.ProtocolData {
	return hysteria2.ProtocolData{
		CertPath:   "/etc/certs/server.crt",
		KeyPath:    "/etc/certs/server.key",
		ServerName: "example.com",
	}
}

func TestValidateOptions(t *testing.T) {
	tests := []struct {
		name    string
		data    hysteria2.ProtocolData
		wantErr bool
	}{
		{name: "valid standard tls", data: validCert()},
		{
			name:    "missing tls",
			data:    hysteria2.ProtocolData{ServerName: "example.com"},
			wantErr: true,
		},
		{
			name: "bandwidth conflict",
			data: hysteria2.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key",
				UpMbps: 100, IgnoreClientBandwidth: true,
			},
			wantErr: true,
		},
		{
			name: "masquerade conflict",
			data: hysteria2.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key",
				MasqueradeURL: "http://127.0.0.1:8080",
				Masquerade:    &hysteria2.MasqueradeObject{Type: hysteria2.MasqueradeTypeProxy, URL: "http://127.0.0.1:8080"},
			},
			wantErr: true,
		},
		{
			name: "invalid bbr profile",
			data: hysteria2.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", BBRProfile: "invalid",
			},
			wantErr: true,
		},
		{
			name: "realm missing stun",
			data: hysteria2.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key",
				Realm: &hysteria2.RealmOptions{
					ServerURL: "https://realm.example.com",
					RealmID:   "test",
				},
			},
			wantErr: true,
		},
		{
			name: "valid acme",
			data: hysteria2.ProtocolData{
				ACME: &hysteria2.ACMEOptions{Domains: []string{"example.com"}, Email: "a@b.com"},
			},
		},
		{
			name: "acme and cert conflict",
			data: hysteria2.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key",
				ACME: &hysteria2.ACMEOptions{Domains: []string{"example.com"}, Email: "a@b.com"},
			},
			wantErr: true,
		},
		{
			name: "acme missing email",
			data: hysteria2.ProtocolData{
				ACME: &hysteria2.ACMEOptions{Domains: []string{"example.com"}},
			},
			wantErr: true,
		},
		{
			name: "ech missing key path",
			data: hysteria2.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", ECHEnabled: true,
			},
			wantErr: true,
		},
		{
			name:    "cert key mismatch",
			data:    hysteria2.ProtocolData{CertPath: "/a.crt"},
			wantErr: true,
		},
		{
			name: "valid bbr conservative",
			data: hysteria2.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", BBRProfile: hysteria2.BBRProfileConservative,
			},
		},
		{
			name: "valid bbr aggressive",
			data: hysteria2.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", BBRProfile: hysteria2.BBRProfileAggressive,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := hysteria2.ValidateOptions(tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateOptions() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTLSMode(t *testing.T) {
	if hysteria2.TLSMode(validCert()) != "standard" {
		t.Fatal("expected standard")
	}
	if hysteria2.TLSMode(hysteria2.ProtocolData{
		ACME: &hysteria2.ACMEOptions{Domains: []string{"example.com"}},
	}) != "acme" {
		t.Fatal("expected acme")
	}
}

func TestValidateMasqueradeObject(t *testing.T) {
	tests := []struct {
		name    string
		m       hysteria2.MasqueradeObject
		wantErr bool
	}{
		{name: "file ok", m: hysteria2.MasqueradeObject{Type: hysteria2.MasqueradeTypeFile, Directory: "/var/www"}},
		{name: "file missing dir", m: hysteria2.MasqueradeObject{Type: hysteria2.MasqueradeTypeFile}, wantErr: true},
		{name: "proxy ok", m: hysteria2.MasqueradeObject{Type: hysteria2.MasqueradeTypeProxy, URL: "http://x"}},
		{name: "proxy missing url", m: hysteria2.MasqueradeObject{Type: hysteria2.MasqueradeTypeProxy}, wantErr: true},
		{name: "string ok", m: hysteria2.MasqueradeObject{Type: hysteria2.MasqueradeTypeString, StatusCode: 200}},
		{name: "string missing status", m: hysteria2.MasqueradeObject{Type: hysteria2.MasqueradeTypeString}, wantErr: true},
		{name: "missing type", m: hysteria2.MasqueradeObject{}, wantErr: true},
		{name: "unknown type", m: hysteria2.MasqueradeObject{Type: "bad"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := validCert()
			data.Masquerade = &tt.m
			err := hysteria2.ValidateOptions(data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateOptions() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateRealm(t *testing.T) {
	valid := hysteria2.RealmOptions{
		ServerURL: "https://realm.example.com", RealmID: "my-realm",
		STUNServers: []string{"stun.l.google.com:19302"},
	}
	tests := []struct {
		name    string
		realm   hysteria2.RealmOptions
		wantErr bool
	}{
		{name: "valid", realm: valid},
		{name: "missing server url", realm: hysteria2.RealmOptions{RealmID: "x", STUNServers: valid.STUNServers}, wantErr: true},
		{name: "missing realm id", realm: hysteria2.RealmOptions{ServerURL: valid.ServerURL, STUNServers: valid.STUNServers}, wantErr: true},
		{name: "invalid realm id", realm: hysteria2.RealmOptions{ServerURL: valid.ServerURL, RealmID: "-bad", STUNServers: valid.STUNServers}, wantErr: true},
		{name: "missing stun", realm: hysteria2.RealmOptions{ServerURL: valid.ServerURL, RealmID: valid.RealmID}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := validCert()
			data.Realm = &tt.realm
			err := hysteria2.ValidateOptions(data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateOptions() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateMasqueradeObject_direct(t *testing.T) {
	if err := hysteria2.ValidateMasqueradeObjectForTest(hysteria2.MasqueradeObject{Type: hysteria2.MasqueradeTypeFile, Directory: "/d"}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRealm_direct(t *testing.T) {
	if err := hysteria2.ValidateRealmForTest(hysteria2.RealmOptions{
		ServerURL: "https://x", RealmID: "id", STUNServers: []string{"s"},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestParseProtocolData(t *testing.T) {
	got, err := hysteria2.ParseProtocolData([]byte(`{"server_name":"example.com"}`))
	if err != nil || got.ServerName != "example.com" {
		t.Fatalf("parse: %#v, %v", got, err)
	}
	_, err = hysteria2.ParseProtocolData([]byte(`not json`))
	if err == nil || !strings.Contains(err.Error(), "parse hysteria2 protocol data") {
		t.Fatalf("expected error, got %v", err)
	}
}

func TestMarshalProtocolData(t *testing.T) {
	raw, err := hysteria2.MarshalProtocolData(hysteria2.ProtocolData{BBRProfile: hysteria2.BBRProfileStandard})
	if err != nil {
		t.Fatal(err)
	}
	var decoded hysteria2.ProtocolData
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.BBRProfile != hysteria2.BBRProfileStandard {
		t.Fatalf("decoded = %#v", decoded)
	}
}
