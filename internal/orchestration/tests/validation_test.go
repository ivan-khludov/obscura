package orchestration_test

import (
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/orchestration"
)

func TestValidateCreateVPNRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     orchestration.CreateVPNRequest
		wantErr string
	}{
		{
			name: "happy path default protocol",
			req: orchestration.CreateVPNRequest{
				Name:     "main",
				Protocol: "",
			},
		},
		{
			name: "tls on non-http",
			req: orchestration.CreateVPNRequest{
				Protocol: "socks5",
				HTTPTLS:  true,
			},
			wantErr: "--tls is only supported for http protocol",
		},
		{
			name: "method on non-shadowsocks",
			req: orchestration.CreateVPNRequest{
				Protocol: "trojan",
				SSMethod: "2022-blake3-aes-128-gcm",
			},
			wantErr: "--method is only supported for shadowsocks protocol",
		},
		{
			name: "shadowsocks compat on non-shadowsocks",
			req: orchestration.CreateVPNRequest{
				Protocol:    "trojan",
				SSShadowTLS: true,
			},
			wantErr: "shadowsocks transport options are only supported for shadowsocks protocol",
		},
		{
			name: "multiplex on unsupported protocol",
			req: orchestration.CreateVPNRequest{
				Protocol:           "socks5",
				MultiplexRequested: true,
			},
			wantErr: "multiplex is only supported for shadowsocks, trojan, vmess, or vless protocol",
		},
		{
			name: "multiplex padding on unsupported protocol",
			req: orchestration.CreateVPNRequest{
				Protocol:                  "http",
				MultiplexPaddingRequested: true,
			},
			wantErr: "multiplex is only supported for shadowsocks, trojan, vmess, or vless protocol",
		},
		{
			name: "multiplex brutal on non-vmess/vless",
			req: orchestration.CreateVPNRequest{
				Protocol:                 "trojan",
				MultiplexBrutalRequested: true,
			},
			wantErr: "--multiplex-brutal is only supported for vmess or vless protocol",
		},
		{
			name: "multiplex brutal up on non-vmess/vless",
			req: orchestration.CreateVPNRequest{
				Protocol:                       "trojan",
				MultiplexBrutalUpMbpsRequested: 100,
			},
			wantErr: "multiplex brutal bandwidth flags are only supported for vmess or vless protocol",
		},
		{
			name: "multiplex brutal down on non-vmess/vless",
			req: orchestration.CreateVPNRequest{
				Protocol:                         "trojan",
				MultiplexBrutalDownMbpsRequested: 100,
			},
			wantErr: "multiplex brutal bandwidth flags are only supported for vmess or vless protocol",
		},
		{
			name: "trojan options on wrong protocol",
			req: orchestration.CreateVPNRequest{
				Protocol: "socks5",
				Trojan:   orchestration.TrojanCreateOptions{ServerName: "example.com"},
			},
			wantErr: "trojan options are only supported for trojan, vmess, or vless protocol",
		},
		{
			name: "wireguard options on wrong protocol",
			req: orchestration.CreateVPNRequest{
				Protocol:  "trojan",
				Wireguard: orchestration.WireguardCreateOptions{MTU: 1400},
			},
			wantErr: "wireguard options are only supported for wireguard protocol",
		},
		{
			name: "hysteria2 options on wrong protocol",
			req: orchestration.CreateVPNRequest{
				Protocol:  "trojan",
				Hysteria2: orchestration.Hysteria2CreateOptions{ServerName: "example.com"},
			},
			wantErr: "hysteria2 options are only supported for hysteria2 protocol",
		},
		{
			name: "tuic options on wrong protocol",
			req: orchestration.CreateVPNRequest{
				Protocol: "trojan",
				TUIC:     orchestration.TUICCreateOptions{ServerName: "example.com"},
			},
			wantErr: "tuic options are only supported for tuic protocol",
		},
		{
			name: "valid trojan with trojan options",
			req: orchestration.CreateVPNRequest{
				Protocol: "trojan",
				Trojan:   orchestration.TrojanCreateOptions{ServerName: "example.com"},
			},
		},
		{
			name: "valid vmess with trojan options",
			req: orchestration.CreateVPNRequest{
				Protocol: "vmess",
				Trojan:   orchestration.TrojanCreateOptions{ServerName: "example.com"},
			},
		},
		{
			name: "valid shadowsocks compat fields",
			req: orchestration.CreateVPNRequest{
				Protocol:    "shadowsocks",
				SSPlugin:    "obfs-local",
				SSMultiplex: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := orchestration.ValidateCreateVPNRequest(tt.req)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}
