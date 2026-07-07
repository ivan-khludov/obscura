package service_test

import (
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/service"
)

func TestNormalizeCreateVPNInputDefaults(t *testing.T) {
	in := service.NormalizeCreateVPNInput(service.CreateVPNInput{})
	if in.Protocol != "socks5" || in.Listen.ListenPort != 1080 {
		t.Fatalf("socks5 defaults: %#v", in)
	}
	in = service.NormalizeCreateVPNInput(service.CreateVPNInput{Protocol: "http"})
	if in.Listen.ListenPort != 8080 {
		t.Fatalf("http port: %d", in.Listen.ListenPort)
	}
	in = service.NormalizeCreateVPNInput(service.CreateVPNInput{Protocol: "shadowsocks"})
	if in.Listen.ListenPort != 8388 {
		t.Fatalf("ss port: %d", in.Listen.ListenPort)
	}
	in = service.NormalizeCreateVPNInput(service.CreateVPNInput{Protocol: "wireguard"})
	if in.Listen.ListenPort != 51820 {
		t.Fatalf("wg port: %d", in.Listen.ListenPort)
	}
	in = service.NormalizeCreateVPNInput(service.CreateVPNInput{Protocol: "trojan"})
	if in.Listen.ListenPort != 443 {
		t.Fatalf("trojan port: %d", in.Listen.ListenPort)
	}
	in = service.NormalizeCreateVPNInput(service.CreateVPNInput{Protocol: "http", HTTPTLS: true})
	if !service.HasHTTPOptionsForTest(in.HTTP) || !in.HTTP.TLS {
		t.Fatalf("http tls merge: %#v", in.HTTP)
	}
	in = service.NormalizeCreateVPNInput(service.CreateVPNInput{
		Protocol: "shadowsocks", SSMethod: "2022-blake3-aes-128-gcm", SSMultiplex: true,
		Listen: domain.ListenOptions{ListenPort: 9000},
	})
	if !service.HasShadowsocksOptionsForTest(in.Shadowsocks) {
		t.Fatal("expected shadowsocks options merged")
	}
	for _, proto := range []string{"vmess", "vless", "hysteria2", "tuic"} {
		got := service.NormalizeCreateVPNInput(service.CreateVPNInput{Protocol: proto})
		if got.Listen.ListenPort != 443 {
			t.Fatalf("%s port=%d", proto, got.Listen.ListenPort)
		}
	}
}

func TestHasHTTPAndShadowsocksOptions(t *testing.T) {
	if service.HasHTTPOptionsForTest(service.HTTPCreateOptions{}) {
		t.Fatal("empty http options")
	}
	if service.HasShadowsocksOptionsForTest(service.ShadowsocksCreateOptions{}) {
		t.Fatal("empty ss options")
	}
}
