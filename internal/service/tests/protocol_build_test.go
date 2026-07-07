package service_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ivan-khludov/obscura/internal/config"
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/firewall"
	"github.com/ivan-khludov/obscura/internal/manifest"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/service"
	"github.com/ivan-khludov/obscura/internal/singboxcheck"
	"github.com/ivan-khludov/obscura/internal/systemd"
)

func TestCreateSpecAndProtocolOptions(t *testing.T) {
	spec := service.CreateSpecForTest(service.CreateVPNInput{
		Name: "web", Protocol: "http", HTTPTLS: true,
		Listen: domain.ListenOptions{ListenPort: 8080},
	})
	if spec.ProtocolOptions == nil {
		t.Fatal("expected http options")
	}
	opts := service.ProtocolOptionsFromInputForTest(service.CreateVPNInput{Protocol: "socks5"})
	if opts != nil {
		t.Fatal("expected nil for socks5")
	}
}

func TestBuildProtocolData(t *testing.T) {
	svc, _ := newTestService(t)
	raw, err := svc.BuildProtocolDataForTest(service.CreateVPNInput{
		Name: "ss", Protocol: "shadowsocks", SSMethod: "2022-blake3-aes-128-gcm",
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8388},
	}, "vpn-ss", protocol.BuildModePreview)
	if err != nil || len(raw) == 0 {
		t.Fatalf("protocol data: err=%v len=%d", err, len(raw))
	}
	_, err = svc.BuildProtocolDataForTest(service.CreateVPNInput{Protocol: "unknown"}, "tag", protocol.BuildModePreview)
	if err == nil {
		t.Fatal("expected unknown protocol error")
	}
}

func TestBuildProtocolDataNoBuilder(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
		ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode: true,
	}
	st := mustOpenStore(t, app.DBPath)
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	reg := customRegistry(t, bareProtocol{})
	svc := service.NewService(app, st, reg, man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	_, err := svc.BuildProtocolDataForTest(service.CreateVPNInput{Protocol: "bare"}, "tag", protocol.BuildModePreview)
	if err == nil {
		t.Fatal("expected no builder error")
	}
}

func TestToVPNConfigAndClientConfigs(t *testing.T) {
	cfg := service.ToVPNConfigForTest(&domain.VPN{Name: "a", Protocol: "socks5", Tag: "vpn-a"})
	if cfg.Name != "a" {
		t.Fatalf("cfg=%#v", cfg)
	}
	clients := service.ToClientConfigsForTest([]domain.Client{{Name: "c", Username: "u", Password: "p", Enabled: true}})
	if len(clients) != 1 {
		t.Fatalf("clients=%#v", clients)
	}
}

func TestSSOptionSetAndPreviewHelpers(t *testing.T) {
	if !service.SSOptionSetForTest(service.CreateVPNInput{SSMultiplex: true}) {
		t.Fatal("expected ss options set")
	}
	if service.PreviewTagForTest("") != "vpn-preview" {
		t.Fatal("empty preview tag")
	}
	if service.PreviewNameForTest("") != "preview" {
		t.Fatal("empty preview name")
	}
}

func TestValidateCreateVPNInputFields(t *testing.T) {
	if err := service.ValidateCreateVPNInputFieldsForTest(service.CreateVPNInput{HTTPTLS: true, Protocol: "socks5"}); err == nil {
		t.Fatal("expected tls protocol error")
	}
	if err := service.ValidateStructuredProtocolOptionOwnershipForTest(service.CreateVPNInput{
		Protocol: "socks5", Trojan: service.TrojanCreateOptions{ServerName: "x"},
	}); err == nil {
		t.Fatal("expected trojan ownership error")
	}
}

func TestValidateCreateVPNProtocolPreview(t *testing.T) {
	svc, _ := newTestService(t)
	err := svc.ValidateCreateVPNProtocolPreviewForTest(context.Background(), service.CreateVPNInput{
		Protocol: "vless",
		VLESS:    service.VLESSCreateOptions{DefaultFlow: "vision", Transport: "grpc", ServerName: "example.com"},
	})
	if err == nil {
		t.Fatal("expected preview validation error")
	}
}

func TestGenerateClientPasswordPaths(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	result, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "ss", Protocol: "shadowsocks", Enabled: false,
		Listen:   domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8388},
		SSMethod: "2022-blake3-aes-128-gcm",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, proto := range []string{"shadowsocks", "wireguard", "vmess"} {
		result.VPN.Protocol = proto
		if _, err := svc.GenerateClientPasswordForTest(result.VPN); err != nil {
			t.Fatalf("%s: %v", proto, err)
		}
	}
}

func TestProtocolOptionsAllTypes(t *testing.T) {
	for _, proto := range []string{"shadowsocks", "wireguard", "trojan", "vmess", "vless", "hysteria2", "tuic"} {
		opts := service.ProtocolOptionsFromInputForTest(service.CreateVPNInput{Protocol: proto})
		if opts == nil {
			t.Fatalf("expected options for %s", proto)
		}
	}
}
