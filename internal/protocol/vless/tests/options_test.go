package vless_test

import (
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol/vless"
)

func TestParseProtocolData(t *testing.T) {
	empty, err := vless.ParseProtocolData(nil)
	if err != nil || empty.ServerName != "" {
		t.Fatalf("empty parse: %#v, %v", empty, err)
	}
	got, err := vless.ParseProtocolData([]byte(`{"server_name":"example.com"}`))
	if err != nil || got.ServerName != "example.com" {
		t.Fatalf("parse: %#v, %v", got, err)
	}
	_, err = vless.ParseProtocolData([]byte(`{`))
	if err == nil || !strings.Contains(err.Error(), "parse vless protocol data") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestMarshalProtocolData(t *testing.T) {
	raw, err := vless.MarshalProtocolData(vless.ProtocolData{ServerName: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "example.com") {
		t.Fatalf("unexpected marshal: %s", raw)
	}
}

func TestTLSMode(t *testing.T) {
	if vless.TLSMode(vless.ProtocolData{RealityEnabled: true}) != "reality" {
		t.Fatal("expected reality mode")
	}
	if vless.TLSMode(vless.ProtocolData{ACME: &vless.ACMEOptions{Domains: []string{"x.com"}}}) != "acme" {
		t.Fatal("expected acme mode")
	}
	if vless.TLSMode(vless.ProtocolData{CertPath: "/a.crt"}) != "standard" {
		t.Fatal("expected standard mode")
	}
}

func TestValidateOptions(t *testing.T) {
	validCert := vless.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
	}
	tests := []struct {
		name    string
		data    vless.ProtocolData
		wantErr bool
		errSub  string
	}{
		{name: "valid standard", data: validCert},
		{
			name: "valid multiplex",
			data: vless.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
				Multiplex: true, MultiplexBrutal: true, MultiplexBrutalUpMbps: 10, MultiplexBrutalDownMbps: 10,
			},
		},
		{
			name: "valid ws transport",
			data: vless.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
				TransportType: "ws", TransportWS: &vless.TransportWS{Path: "/x"},
			},
		},
		{
			name: "valid acme",
			data: vless.ProtocolData{
				ServerName: "example.com",
				ACME:       &vless.ACMEOptions{Domains: []string{"example.com"}, Email: "a@b.c"},
			},
		},
		{
			name: "valid reality",
			data: vless.ProtocolData{
				RealityEnabled: true, RealityPrivateKey: "key", RealityShortIDs: []string{"abcd"},
				RealityHandshakeServer: "www.bing.com",
			},
		},
		{name: "missing tls", data: vless.ProtocolData{ServerName: "example.com"}, wantErr: true},
		{
			name: "conflicting tls modes",
			data: vless.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", RealityEnabled: true,
				RealityPrivateKey: "k", RealityShortIDs: []string{"ab"},
				RealityHandshakeServer: "x.com",
			},
			wantErr: true,
		},
		{
			name: "fallback rejected",
			data: vless.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", FallbackServer: "127.0.0.1",
			},
			wantErr: true,
			errSub:  "tls fallback is only supported for trojan",
		},
		{
			name: "multiplex brutal invalid",
			data: vless.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", MultiplexBrutal: true,
			},
			wantErr: true,
			errSub:  "multiplex brutal requires positive",
		},
		{
			name: "unsupported default flow",
			data: vless.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", DefaultFlow: "bad-flow",
			},
			wantErr: true,
			errSub:  "unsupported default flow",
		},
		{
			name: "vision flow with transport",
			data: vless.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", DefaultFlow: vless.FlowVision,
				TransportType: "ws", TransportWS: &vless.TransportWS{Path: "/"},
			},
			wantErr: true,
			errSub:  "direct transport",
		},
		{
			name: "invalid acme email",
			data: vless.ProtocolData{
				ACME: &vless.ACMEOptions{Domains: []string{"example.com"}},
			},
			wantErr: true,
		},
		{
			name: "ech without key path",
			data: vless.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", ECHEnabled: true,
			},
			wantErr: true,
		},
		{
			name:    "cert without key",
			data:    vless.ProtocolData{CertPath: "/a.crt"},
			wantErr: true,
		},
		{
			name: "invalid reality params",
			data: vless.ProtocolData{
				RealityEnabled: true, RealityPrivateKey: "", RealityShortIDs: nil,
			},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := vless.ValidateOptions(tc.data)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateOptions() err=%v wantErr=%v", err, tc.wantErr)
			}
			if tc.errSub != "" && (err == nil || !strings.Contains(err.Error(), tc.errSub)) {
				t.Fatalf("ValidateOptions() err=%v want substring %q", err, tc.errSub)
			}
		})
	}
}

func TestValidateFlowTransport(t *testing.T) {
	tests := []struct {
		flow      string
		transport string
		wantErr   bool
	}{
		{vless.FlowVision, "", false},
		{vless.FlowVision, "grpc", true},
		{vless.FlowVision, "ws", true},
		{vless.FlowVision, "quic", true},
		{"", "grpc", false},
		{"", "ws", false},
		{"", "tcp", false},
	}
	for _, tc := range tests {
		err := vless.ValidateFlowTransport(tc.flow, tc.transport)
		if tc.wantErr && err == nil {
			t.Fatalf("ValidateFlowTransport(%q, %q) expected error", tc.flow, tc.transport)
		}
		if !tc.wantErr && err != nil {
			t.Fatalf("ValidateFlowTransport(%q, %q) unexpected error: %v", tc.flow, tc.transport, err)
		}
		if tc.wantErr && err != nil && !strings.Contains(err.Error(), "direct transport") {
			t.Fatalf("unexpected error text: %v", err)
		}
	}
}

func TestValidateClientFlow(t *testing.T) {
	if err := vless.ValidateClientFlow(""); err != nil {
		t.Fatal(err)
	}
	if err := vless.ValidateClientFlow(vless.FlowVision); err != nil {
		t.Fatal(err)
	}
	if err := vless.ValidateClientFlow("bad"); err == nil {
		t.Fatal("expected unsupported flow error")
	}
}

func TestTransportModesAndFlowModes(t *testing.T) {
	if len(vless.TransportModes) == 0 || len(vless.FlowModes) == 0 {
		t.Fatal("expected non-empty mode lists")
	}
	if vless.DefaultRealityHandshakePort != 443 {
		t.Fatalf("unexpected default port: %d", vless.DefaultRealityHandshakePort)
	}
	if len(vless.DefaultALPN) == 0 {
		t.Fatal("expected default alpn")
	}
}
