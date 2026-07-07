package tui_test

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/tui"
)

func TestBuildCreateVPNRequest_UsesSharedOptionBuilders(t *testing.T) {
	state := tui.WizardStateForTest{
		VPNName: "trojan1", Protocol: "trojan", ListenPort: 443, ClientName: "phone",
		TrojanServerName: "example.com", TrojanTransport: "grpc", TrojanTransportServiceName: "svc",
		TrojanMultiplex: true, TrojanMultiplexPadding: true, TrojanFallbackPort: 8080,
		VlessFlow: orchestration.VLESSFlowVision(), VlessReality: true, RealityUTLSFingerprint: "chrome",
	}
	got := tui.BuildCreateVPNRequestForTest(state)
	wantTrojan := orchestration.BuildTrojanCreateOptionsFromFields(
		"example.com", "grpc", "", "", "svc", true, true, 8080,
	)
	wantVLESS := orchestration.BuildVLESSCreateOptionsFromFields(
		orchestration.VLESSFlowVision(), true, "chrome", wantTrojan,
	)
	if diff := cmp.Diff(wantTrojan, got.Trojan); diff != "" {
		t.Fatalf("trojan mapping mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(wantVLESS, got.VLESS); diff != "" {
		t.Fatalf("vless mapping mismatch (-want +got):\n%s", diff)
	}
}

func TestBuildCreateVPNRequest_Hysteria2AndTUICOptions(t *testing.T) {
	hy2State := tui.WizardStateForTest{
		VPNName:          "hy2",
		Protocol:         "hysteria2",
		ListenPort:       443,
		ClientName:       "phone",
		Hy2ServerName:    "example.com",
		Hy2UpMbps:        100,
		Hy2DownMbps:      200,
		Hy2ObfsPassword:  "auto",
		Hy2MasqueradeURL: "file:///var/www",
	}
	hy2Req := tui.BuildCreateVPNRequestForTest(hy2State)
	wantHy2 := orchestration.BuildHysteria2CreateOptions("example.com", 100, 200, false, "auto", "file:///var/www")
	if diff := cmp.Diff(wantHy2, hy2Req.Hysteria2); diff != "" {
		t.Fatalf("hysteria2 mapping mismatch (-want +got):\n%s", diff)
	}

	tuicState := tui.WizardStateForTest{
		VPNName:               "tuic",
		Protocol:              "tuic",
		ListenPort:            443,
		ClientName:            "phone",
		TuicServerName:        "example.com",
		TuicCongestionControl: orchestration.TUICCongestionByIndex(2),
		TuicZeroRTT:           true,
	}
	tuicReq := tui.BuildCreateVPNRequestForTest(tuicState)
	wantTUIC := orchestration.BuildTUICCreateOptions("example.com", orchestration.TUICCongestionByIndex(2), true)
	if diff := cmp.Diff(wantTUIC, tuicReq.TUIC); diff != "" {
		t.Fatalf("tuic mapping mismatch (-want +got):\n%s", diff)
	}
}

func TestWizardShowCreatePortInput_UsesOrchestrationDefaults(t *testing.T) {
	tests := []struct {
		protocol string
		wantPort int
	}{
		{protocol: "http", wantPort: 8080},
		{protocol: "socks5", wantPort: 1080},
		{protocol: "trojan", wantPort: 443},
		{protocol: "wireguard", wantPort: 51820},
	}

	for _, tt := range tests {
		t.Run(tt.protocol, func(t *testing.T) {
			m := tui.NewModelForTest(nil, nil)
			m.SetMode(tui.ModeWizard)
			m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Protocol: tt.protocol})
			next, _ := m.WizardShowCreatePortInput()
			if got := orchestration.DefaultListenPort(tt.protocol); got != tt.wantPort {
				t.Fatalf("default port mismatch for protocol %s: %d != %d", tt.protocol, got, tt.wantPort)
			}
			wantPrompt := fmt.Sprintf("Port [%d]:", tt.wantPort)
			if next.Wizard().Prompt != wantPrompt {
				t.Fatalf("wizard/orchestration default port mismatch for protocol %s: %q != %q", tt.protocol, next.Wizard().Prompt, wantPrompt)
			}
		})
	}
}

func TestBuildCreateVPNRequest_ProtocolMatrix(t *testing.T) {
	tests := []struct {
		name     string
		state    tui.WizardStateForTest
		validate func(*testing.T, orchestration.CreateVPNRequest)
	}{
		{
			name:  "socks5 minimal",
			state: tui.WizardStateForTest{VPNName: "s1", Protocol: "socks5", ListenPort: 1080, ClientName: "phone"},
			validate: func(t *testing.T, req orchestration.CreateVPNRequest) {
				t.Helper()
				if req.Protocol != "socks5" || req.Listen.ListenPort != 1080 {
					t.Fatalf("unexpected socks5 request: %#v", req)
				}
			},
		},
		{
			name:  "http tls",
			state: tui.WizardStateForTest{VPNName: "h1", Protocol: "http", ListenPort: 8080, ClientName: "phone", HTTPTLS: true},
			validate: func(t *testing.T, req orchestration.CreateVPNRequest) {
				t.Helper()
				if !req.HTTPTLS || !req.HTTP.TLS {
					t.Fatalf("expected http tls in request: %#v", req)
				}
			},
		},
		{
			name: "shadowsocks",
			state: tui.WizardStateForTest{
				VPNName: "ss1", Protocol: "shadowsocks", ListenPort: 8388, ClientName: "phone",
				SSMethod: "2022-blake3-aes-128-gcm", SSMultiplex: true, SSShadowTLS: true,
			},
			validate: func(t *testing.T, req orchestration.CreateVPNRequest) {
				t.Helper()
				if req.Shadowsocks.Method == "" || !req.SSMultiplex {
					t.Fatalf("expected shadowsocks mapping in request: %#v", req)
				}
			},
		},
		{
			name: "wireguard",
			state: tui.WizardStateForTest{
				VPNName: "wg1", Protocol: "wireguard", ListenPort: 51820, ClientName: "phone",
				WGAddress: "10.8.0.1/24", WGSystem: true, WGMTU: 1408,
			},
			validate: func(t *testing.T, req orchestration.CreateVPNRequest) {
				t.Helper()
				if len(req.Wireguard.Address) == 0 || req.Wireguard.Address[0] != "10.8.0.1/24" {
					t.Fatalf("expected wireguard address in request: %#v", req)
				}
			},
		},
		{
			name: "vmess",
			state: tui.WizardStateForTest{
				VPNName: "vm1", Protocol: "vmess", ListenPort: 443, ClientName: "phone",
				VMessNoTLS: true, TrojanTransport: "grpc", TrojanTransportServiceName: "svc",
			},
			validate: func(t *testing.T, req orchestration.CreateVPNRequest) {
				t.Helper()
				if !req.VMess.NoTLS || req.VMess.TransportServiceName != "svc" {
					t.Fatalf("expected vmess mapping in request: %#v", req)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tui.BuildCreateVPNRequestForTest(tt.state)
			tt.validate(t, req)
		})
	}
}
