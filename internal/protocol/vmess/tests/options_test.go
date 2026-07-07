package vmess_test

import (
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol/vmess"
)

func TestParseProtocolData_hook(t *testing.T) {
	restore := vmess.SetParseProtocolDataHookForTest(func([]byte) (vmess.ProtocolData, error) {
		return vmess.ProtocolData{ServerName: "hooked"}, nil
	})
	defer restore()
	data, err := vmess.ParseProtocolData([]byte(`{"server_name":"ignored"}`))
	if err != nil || data.ServerName != "hooked" {
		t.Fatalf("ParseProtocolData() = %#v, %v", data, err)
	}
}

func TestParseProtocolData(t *testing.T) {
	empty, err := vmess.ParseProtocolData(nil)
	if err != nil || empty.ServerName != "" {
		t.Fatalf("empty parse: %#v, %v", empty, err)
	}
	got, err := vmess.ParseProtocolData([]byte(`{"server_name":"example.com"}`))
	if err != nil || got.ServerName != "example.com" {
		t.Fatalf("parse: %#v, %v", got, err)
	}
	_, err = vmess.ParseProtocolData([]byte(`{`))
	if err == nil || !strings.Contains(err.Error(), "parse vmess protocol data") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestMarshalProtocolData(t *testing.T) {
	raw, err := vmess.MarshalProtocolData(vmess.ProtocolData{ServerName: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "example.com") {
		t.Fatalf("unexpected marshal: %s", raw)
	}
}

func TestTLSMode(t *testing.T) {
	if vmess.TLSMode(vmess.ProtocolData{TLSDisabled: true}) != "none" {
		t.Fatal("expected none mode")
	}
	if vmess.TLSMode(vmess.ProtocolData{RealityEnabled: true}) != "reality" {
		t.Fatal("expected reality mode")
	}
	if vmess.TLSMode(vmess.ProtocolData{ACME: &vmess.ACMEOptions{Domains: []string{"x.com"}}}) != "acme" {
		t.Fatal("expected acme mode")
	}
	if vmess.TLSMode(vmess.ProtocolData{CertPath: "/a.crt"}) != "standard" {
		t.Fatal("expected standard mode")
	}
}

func TestValidateOptions(t *testing.T) {
	validCert := vmess.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
	}
	tests := []struct {
		name    string
		data    vmess.ProtocolData
		wantErr bool
		errSub  string
	}{
		{name: "valid standard", data: validCert},
		{
			name: "valid no tls",
			data: vmess.ProtocolData{TLSDisabled: true},
		},
		{
			name: "valid multiplex",
			data: vmess.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
				Multiplex: true, MultiplexBrutal: true, MultiplexBrutalUpMbps: 10, MultiplexBrutalDownMbps: 10,
			},
		},
		{
			name: "valid ws transport",
			data: vmess.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com",
				TransportType: "ws", TransportWS: &vmess.TransportWS{Path: "/x"},
			},
		},
		{
			name: "valid acme",
			data: vmess.ProtocolData{
				ServerName: "example.com",
				ACME:       &vmess.ACMEOptions{Domains: []string{"example.com"}, Email: "a@b.c"},
			},
		},
		{
			name: "valid reality",
			data: vmess.ProtocolData{
				RealityEnabled: true, RealityPrivateKey: "key", RealityShortIDs: []string{"abcd"},
				RealityHandshakeServer: "www.bing.com",
			},
		},
		{
			name: "invalid reality fingerprint",
			data: vmess.ProtocolData{
				RealityEnabled: true, RealityPrivateKey: "key", RealityShortIDs: []string{"abcd"},
				RealityHandshakeServer: "www.bing.com", RealityUTLSFingerprint: "bad",
			},
			wantErr: true,
		},
		{
			name: "mismatched cert key pair",
			data: vmess.ProtocolData{
				CertPath: "/a.crt", ServerName: "example.com",
			},
			wantErr: true,
		},
		{name: "missing tls", data: vmess.ProtocolData{ServerName: "example.com"}, wantErr: true},
		{
			name: "conflicting tls modes",
			data: vmess.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", RealityEnabled: true,
				RealityPrivateKey: "k", RealityShortIDs: []string{"ab"},
				RealityHandshakeServer: "x.com",
			},
			wantErr: true,
		},
		{
			name: "fallback rejected with tls",
			data: vmess.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", FallbackPort: 8080,
			},
			wantErr: true,
			errSub:  "tls fallback is only supported for trojan",
		},
		{
			name: "fallback rejected without tls",
			data: vmess.ProtocolData{
				TLSDisabled: true, FallbackServer: "127.0.0.1",
			},
			wantErr: true,
			errSub:  "tls fallback is only supported for trojan",
		},
		{
			name: "multiplex brutal invalid",
			data: vmess.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", MultiplexBrutal: true,
			},
			wantErr: true,
			errSub:  "multiplex brutal requires positive",
		},
		{
			name: "invalid acme email",
			data: vmess.ProtocolData{
				ACME: &vmess.ACMEOptions{Domains: []string{"example.com"}},
			},
			wantErr: true,
		},
		{
			name: "ech without key path",
			data: vmess.ProtocolData{
				CertPath: "/a.crt", KeyPath: "/a.key", ECHEnabled: true,
			},
			wantErr: true,
		},
		{
			name: "invalid transport no tls",
			data: vmess.ProtocolData{
				TLSDisabled: true, TransportType: "ws",
			},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := vmess.ValidateOptions(tc.data)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateOptions() err=%v wantErr=%v", err, tc.wantErr)
			}
			if tc.errSub != "" && (err == nil || !strings.Contains(err.Error(), tc.errSub)) {
				t.Fatalf("ValidateOptions() err=%v want substring %q", err, tc.errSub)
			}
		})
	}
}

func TestTransportModes(t *testing.T) {
	if len(vmess.TransportModes) == 0 {
		t.Fatal("expected non-empty transport modes")
	}
	if vmess.DefaultRealityHandshakePort != 443 {
		t.Fatalf("unexpected default port: %d", vmess.DefaultRealityHandshakePort)
	}
	if len(vmess.DefaultALPN) == 0 {
		t.Fatal("expected default alpn")
	}
}
