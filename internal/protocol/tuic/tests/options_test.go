package tuic_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol/tuic"
)

func validCert() tuic.ProtocolData {
	return tuic.ProtocolData{
		CertPath:   "/etc/certs/server.crt",
		KeyPath:    "/etc/certs/server.key",
		ServerName: "example.com",
	}
}

func TestValidateOptions(t *testing.T) {
	tests := []struct {
		name    string
		data    tuic.ProtocolData
		wantErr bool
	}{
		{name: "valid standard tls", data: validCert()},
		{
			name:    "missing tls",
			data:    tuic.ProtocolData{ServerName: "example.com"},
			wantErr: true,
		},
		{
			name: "invalid congestion control",
			data: tuic.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key",
				CongestionControl: "reno",
			},
			wantErr: true,
		},
		{
			name: "valid bbr",
			data: tuic.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key",
				CongestionControl: tuic.CongestionBBR,
			},
		},
		{
			name: "valid new_reno",
			data: tuic.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key",
				CongestionControl: tuic.CongestionNewReno,
			},
		},
		{
			name: "valid acme",
			data: tuic.ProtocolData{
				ACME: &tuic.ACMEOptions{Domains: []string{"example.com"}, Email: "a@b.com"},
			},
		},
		{
			name: "acme and cert conflict",
			data: tuic.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key",
				ACME: &tuic.ACMEOptions{Domains: []string{"example.com"}, Email: "a@b.com"},
			},
			wantErr: true,
		},
		{
			name: "acme missing email",
			data: tuic.ProtocolData{
				ACME: &tuic.ACMEOptions{Domains: []string{"example.com"}},
			},
			wantErr: true,
		},
		{
			name: "ech missing key path",
			data: tuic.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", ECHEnabled: true,
			},
			wantErr: true,
		},
		{
			name:    "cert key mismatch",
			data:    tuic.ProtocolData{CertPath: "/a.crt"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tuic.ValidateOptions(tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateOptions() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTLSMode(t *testing.T) {
	if tuic.TLSMode(validCert()) != "standard" {
		t.Fatal("expected standard")
	}
	if tuic.TLSMode(tuic.ProtocolData{
		ACME: &tuic.ACMEOptions{Domains: []string{"example.com"}},
	}) != "acme" {
		t.Fatal("expected acme")
	}
}

func TestParseProtocolData(t *testing.T) {
	got, err := tuic.ParseProtocolData([]byte(`{"server_name":"example.com"}`))
	if err != nil || got.ServerName != "example.com" {
		t.Fatalf("parse: %#v, %v", got, err)
	}
	_, err = tuic.ParseProtocolData([]byte(`not json`))
	if err == nil || !strings.Contains(err.Error(), "parse tuic protocol data") {
		t.Fatalf("expected error, got %v", err)
	}
}

func TestMarshalProtocolData(t *testing.T) {
	raw, err := tuic.MarshalProtocolData(tuic.ProtocolData{CongestionControl: tuic.CongestionBBR})
	if err != nil {
		t.Fatal(err)
	}
	var decoded tuic.ProtocolData
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.CongestionControl != tuic.CongestionBBR {
		t.Fatalf("decoded = %#v", decoded)
	}
}
