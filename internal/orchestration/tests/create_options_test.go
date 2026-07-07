package orchestration_test

import (
	"testing"

	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/protocol/hysteria2"
	"github.com/ivan-khludov/obscura/internal/protocol/vless"
	"github.com/ivan-khludov/obscura/internal/protocol/wireguard"
)

func TestBuildTrojanCreateOptions(t *testing.T) {
	base := orchestration.TrojanCreateOptions{ServerName: "example.com"}
	out := orchestration.BuildTrojanCreateOptions(base, true, true, false)
	if !out.Multiplex || !out.MultiplexPadding {
		t.Fatal("expected multiplex flags")
	}
	if out.ServerName != "example.com" {
		t.Fatal("expected base fields preserved")
	}

	stub := orchestration.BuildTrojanCreateOptions(orchestration.TrojanCreateOptions{}, false, false, true)
	if stub.FallbackServer != "127.0.0.1" || stub.FallbackPort != 8080 {
		t.Fatalf("expected fallback stub defaults, got %q:%d", stub.FallbackServer, stub.FallbackPort)
	}

	withPort := orchestration.BuildTrojanCreateOptionsFromFields(
		"example.com", "ws", "/path", "host", "svc", true, true, 9090,
	)
	if withPort.FallbackPort != 9090 || withPort.FallbackServer != "127.0.0.1" {
		t.Fatalf("unexpected fallback: %q:%d", withPort.FallbackServer, withPort.FallbackPort)
	}
	if withPort.Transport != "ws" {
		t.Fatalf("transport = %q", withPort.Transport)
	}
}

func TestBuildVMessCreateOptions(t *testing.T) {
	trojan := orchestration.TrojanCreateOptions{
		ServerName:       "example.com",
		Multiplex:        true,
		MultiplexPadding: true,
		Transport:        "grpc",
	}
	out := orchestration.BuildVMessCreateOptions(
		orchestration.VMessCreateOptions{NoTLS: true},
		trojan, true, 100, 200,
	)
	if out.ServerName != "example.com" || !out.Multiplex || !out.MultiplexBrutal {
		t.Fatalf("unexpected vmess options: %+v", out)
	}
	if out.MultiplexBrutalUpMbps != 100 || out.MultiplexBrutalDownMbps != 200 {
		t.Fatal("expected brutal bandwidth")
	}

	fromFields := orchestration.BuildVMessCreateOptionsFromFields(true, trojan)
	if !fromFields.NoTLS || fromFields.ServerName != "example.com" {
		t.Fatal("expected from-fields vmess")
	}
}

func TestBuildVLESSCreateOptions(t *testing.T) {
	trojan := orchestration.TrojanCreateOptions{ServerName: "example.com", Multiplex: true}
	out := orchestration.BuildVLESSCreateOptions(
		orchestration.VLESSCreateOptions{DefaultFlow: "xtls-rprx-vision"},
		trojan, false, 0, 0,
	)
	if out.DefaultFlow != vless.FlowVision {
		t.Fatalf("flow = %q, want %q", out.DefaultFlow, vless.FlowVision)
	}
	if out.ServerName != "example.com" {
		t.Fatal("expected trojan fields copied")
	}

	fromFields := orchestration.BuildVLESSCreateOptionsFromFields(
		vless.FlowVision, true, "chrome", orchestration.TrojanCreateOptions{
			ServerName:             "example.com",
			Reality:                true,
			RealityUTLSFingerprint: "chrome",
		},
	)
	if !fromFields.Reality || fromFields.RealityUTLSFingerprint != "chrome" {
		t.Fatalf("unexpected from-fields vless: %+v", fromFields)
	}
}

func TestBuildShadowsocksCreateOptions(t *testing.T) {
	out := orchestration.BuildShadowsocksCreateOptions(
		"2022-blake3-aes-128-gcm", "obfs-local", "obfs=tls",
		true, true, true, "www.bing.com", 443, true, 8388,
	)
	if out.Method != "2022-blake3-aes-128-gcm" || out.ListenPort != 8388 {
		t.Fatalf("unexpected ss options: %+v", out)
	}
}

func TestBuildWireguardCreateOptions(t *testing.T) {
	out := orchestration.BuildWireguardCreateOptions(true, "", 1400)
	if len(out.Address) != 1 || out.Address[0] != wireguard.DefaultAddress {
		t.Fatalf("address = %v, want default", out.Address)
	}
	if out.MTU != 1400 || !out.System {
		t.Fatal("expected mtu and system flag")
	}
}

func TestBuildTUICCreateOptions(t *testing.T) {
	out := orchestration.BuildTUICCreateOptions("example.com", "bbr", true)
	if out.ServerName != "example.com" || out.CongestionControl != "bbr" || !out.ZeroRTTHandshake {
		t.Fatalf("unexpected tuic options: %+v", out)
	}
}

func TestBuildHysteria2CreateOptions(t *testing.T) {
	t.Run("file masquerade", func(t *testing.T) {
		out := orchestration.BuildHysteria2CreateOptions("example.com", 100, 200, false, "secret", "file:///var/www")
		if out.MasqueradeType != hysteria2.MasqueradeTypeFile || out.MasqueradeDirectory != "/var/www" {
			t.Fatalf("unexpected file masquerade: %+v", out)
		}
		if out.ObfsPassword != "secret" {
			t.Fatal("expected obfs password")
		}
	})
	t.Run("proxy masquerade", func(t *testing.T) {
		out := orchestration.BuildHysteria2CreateOptions("example.com", 0, 0, true, "", "https://example.com")
		if out.MasqueradeType != hysteria2.MasqueradeTypeProxy || out.MasqueradeProxyURL != "https://example.com" {
			t.Fatalf("unexpected proxy masquerade: %+v", out)
		}
		if !out.IgnoreClientBandwidth {
			t.Fatal("expected ignore client bandwidth")
		}
	})
	t.Run("http proxy masquerade", func(t *testing.T) {
		out := orchestration.BuildHysteria2CreateOptions("example.com", 0, 0, false, "", "http://localhost")
		if out.MasqueradeType != hysteria2.MasqueradeTypeProxy {
			t.Fatal("expected proxy type for http URL")
		}
	})
	t.Run("plain masquerade url", func(t *testing.T) {
		out := orchestration.BuildHysteria2CreateOptions("example.com", 0, 0, false, "", "hello")
		if out.MasqueradeURL != "hello" {
			t.Fatalf("masquerade url = %q", out.MasqueradeURL)
		}
	})
}
