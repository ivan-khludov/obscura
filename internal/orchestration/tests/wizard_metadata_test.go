package orchestration_test

import (
	"testing"

	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/protocol/tuic"
	"github.com/ivan-khludov/obscura/internal/protocol/vless"
	"github.com/ivan-khludov/obscura/internal/protocol/wireguard"
)

func TestShadowsocksMethods(t *testing.T) {
	methods := orchestration.ShadowsocksMethods()
	if len(methods) == 0 {
		t.Fatal("expected non-empty methods")
	}
}

func TestDefaultShadowsocksMethod(t *testing.T) {
	if orchestration.DefaultShadowsocksMethod() == "" {
		t.Fatal("expected default method")
	}
}

func TestShadowsocksTransportModes(t *testing.T) {
	if len(orchestration.ShadowsocksTransportModes()) == 0 {
		t.Fatal("expected transport modes")
	}
}

func TestDefaultShadowsocksHandshake(t *testing.T) {
	if orchestration.DefaultShadowsocksHandshake() == "" {
		t.Fatal("expected default handshake")
	}
}

func TestInboundTransportModes(t *testing.T) {
	if len(orchestration.InboundTransportModes("vmess")) == 0 {
		t.Fatal("expected vmess transport modes")
	}
	if len(orchestration.InboundTransportModes("vless")) == 0 {
		t.Fatal("expected vless transport modes")
	}
	if len(orchestration.InboundTransportModes("trojan")) == 0 {
		t.Fatal("expected default trojan transport modes")
	}
}

func TestVLESSFlowModes(t *testing.T) {
	if len(orchestration.VLESSFlowModes()) == 0 {
		t.Fatal("expected flow modes")
	}
}

func TestVLESSFlowByIndex(t *testing.T) {
	modes := orchestration.VLESSFlowModes()
	for i, mode := range modes {
		got := orchestration.VLESSFlowByIndex(i)
		if mode == "XTLS Vision" && got != vless.FlowVision {
			t.Fatalf("index %d = %q, want vision flow", i, got)
		}
		if mode != "XTLS Vision" && got != "" {
			t.Fatalf("index %d = %q, want empty", i, got)
		}
	}
	if orchestration.VLESSFlowByIndex(-1) != "" || orchestration.VLESSFlowByIndex(len(modes)) != "" {
		t.Fatal("expected empty for out-of-range index")
	}
}

func TestVLESSFlowVision(t *testing.T) {
	if orchestration.VLESSFlowVision() != vless.FlowVision {
		t.Fatal("expected canonical vision flow")
	}
}

func TestWireguardDefaults(t *testing.T) {
	addr, mtu := orchestration.WireguardDefaults()
	if addr != wireguard.DefaultAddress || mtu != wireguard.DefaultMTU {
		t.Fatalf("defaults = %q:%d", addr, mtu)
	}
}

func TestTUICCongestionPickerModes(t *testing.T) {
	modes := orchestration.TUICCongestionPickerModes()
	if len(modes) != 3 {
		t.Fatalf("modes = %v", modes)
	}
}

func TestTUICCongestionByIndex(t *testing.T) {
	tests := []struct {
		idx  int
		want string
	}{
		{0, tuic.CongestionCubic},
		{1, tuic.CongestionNewReno},
		{2, tuic.CongestionBBR},
		{3, tuic.CongestionCubic},
		{-1, tuic.CongestionCubic},
	}
	for _, tt := range tests {
		if got := orchestration.TUICCongestionByIndex(tt.idx); got != tt.want {
			t.Fatalf("TUICCongestionByIndex(%d) = %q, want %q", tt.idx, got, tt.want)
		}
	}
}

func TestHTTPTLSEnabledFromVPN(t *testing.T) {
	if orchestration.HTTPTLSEnabledFromVPN(orchestration.VPNView{Protocol: "socks5"}) {
		t.Fatal("expected false for non-http")
	}
	if orchestration.HTTPTLSEnabledFromVPN(orchestration.VPNView{
		Protocol:     "http",
		ProtocolData: []byte("{invalid"),
	}) {
		t.Fatal("expected false for parse error")
	}
	if orchestration.HTTPTLSEnabledFromVPN(orchestration.VPNView{
		Protocol:     "http",
		ProtocolData: []byte(`{"tls":false}`),
	}) {
		t.Fatal("expected false when tls disabled")
	}
	if !orchestration.HTTPTLSEnabledFromVPN(orchestration.VPNView{
		Protocol:     "HTTP",
		ProtocolData: []byte(`{"tls":true}`),
	}) {
		t.Fatal("expected true when tls enabled")
	}
}
