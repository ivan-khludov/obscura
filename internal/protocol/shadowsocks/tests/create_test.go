package shadowsocks_test

import (
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/protocol/shadowsocks"
	"github.com/ivan-khludov/obscura/internal/protocol/testutil"
)

func TestBuildProtocolData_previewWithoutShadowTLS(t *testing.T) {
	adapter := &shadowsocks.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	raw, err := adapter.BuildProtocolData(ctx, domain.CreateVPNSpec{}, "vpn-ss", protocol.BuildModePreview)
	if err != nil {
		t.Fatal(err)
	}
	data, err := shadowsocks.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if data.Method != shadowsocks.DefaultMethod {
		t.Fatalf("method = %q", data.Method)
	}
	if data.ServerPassword != "preview-shadowsocks-server-key" {
		t.Fatalf("server password = %q", data.ServerPassword)
	}
	if data.ShadowTLS {
		t.Fatal("expected shadowtls disabled")
	}
}

func TestBuildProtocolData_ShadowTLSModes(t *testing.T) {
	adapter := &shadowsocks.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		Protocol: domain.ProtocolShadowsocks,
		ProtocolOptions: shadowsocks.CreateOptions{
			ShadowTLS:          true,
			ShadowTLSHandshake: shadowsocks.DefaultShadowTLSHandshake,
			ListenPort:         443,
		},
	}

	previewRaw, err := adapter.BuildProtocolData(ctx, spec, "vpn-ss", protocol.BuildModePreview)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	preview, err := shadowsocks.ParseProtocolData(previewRaw)
	if err != nil {
		t.Fatalf("parse preview: %v", err)
	}
	if preview.ServerPassword != "preview-shadowsocks-server-key" {
		t.Fatalf("unexpected preview server password: %q", preview.ServerPassword)
	}
	if preview.ShadowTLSPassword != "preview-shadowtls-password" {
		t.Fatalf("unexpected preview shadowtls password: %q", preview.ShadowTLSPassword)
	}
	if preview.ShadowTLSBackendPort != 10443 {
		t.Fatalf("unexpected preview backend port: %d", preview.ShadowTLSBackendPort)
	}

	provisionRaw, err := adapter.BuildProtocolData(ctx, spec, "vpn-ss", protocol.BuildModeProvision)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	provision, err := shadowsocks.ParseProtocolData(provisionRaw)
	if err != nil {
		t.Fatalf("parse provision: %v", err)
	}
	if provision.ServerPassword == "" || provision.ServerPassword == "preview-shadowsocks-server-key" {
		t.Fatalf("unexpected provision server password: %q", provision.ServerPassword)
	}
	if provision.ShadowTLSPassword == "" || provision.ShadowTLSPassword == "preview-shadowtls-password" {
		t.Fatalf("unexpected provision shadowtls password: %q", provision.ShadowTLSPassword)
	}
	if provision.ShadowTLSBackendPort == 0 {
		t.Fatal("expected shadowtls backend port to be set")
	}
}

func TestBuildProtocolData_previewShadowTLSOverflowPort(t *testing.T) {
	adapter := &shadowsocks.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		ProtocolOptions: shadowsocks.CreateOptions{
			ShadowTLS:  true,
			ListenPort: 60000,
		},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-ss", protocol.BuildModePreview)
	if err != nil {
		t.Fatal(err)
	}
	data, err := shadowsocks.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if data.ShadowTLSBackendPort != 40000 {
		t.Fatalf("backend port = %d, want 40000", data.ShadowTLSBackendPort)
	}
	if data.ShadowTLSHandshake != shadowsocks.DefaultShadowTLSHandshake {
		t.Fatalf("handshake = %q", data.ShadowTLSHandshake)
	}
}

func TestBuildProtocolData_multiplexWithoutPadding(t *testing.T) {
	adapter := &shadowsocks.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		ProtocolOptions: shadowsocks.CreateOptions{
			Multiplex: true,
		},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-ss", protocol.BuildModePreview)
	if err != nil {
		t.Fatal(err)
	}
	data, err := shadowsocks.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !data.Multiplex || data.MultiplexPadding {
		t.Fatalf("unexpected multiplex flags: %#v", data)
	}
}

func TestBuildProtocolData_chachaMethodRejected(t *testing.T) {
	adapter := &shadowsocks.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		ProtocolOptions: shadowsocks.CreateOptions{
			Method: "2022-blake3-chacha20-poly1305",
		},
	}
	_, err := adapter.BuildProtocolData(ctx, spec, "vpn-ss", protocol.BuildModeProvision)
	if err == nil || !strings.Contains(err.Error(), "multi-user") {
		t.Fatalf("expected chacha error, got %v", err)
	}
}

func TestBuildProtocolData_invalidOptionsType(t *testing.T) {
	adapter := &shadowsocks.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{ProtocolOptions: "bad"}
	_, err := adapter.BuildProtocolData(ctx, spec, "vpn-ss", protocol.BuildModePreview)
	if err == nil || !strings.Contains(err.Error(), "unexpected type") {
		t.Fatalf("expected type error, got %v", err)
	}
}

func TestBuildProtocolData_createOptionsFromSpec(t *testing.T) {
	adapter := &shadowsocks.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	opts := shadowsocks.CreateOptions{Plugin: "obfs-local", PluginOpts: shadowsocks.DefaultObfsPluginOpts}
	for _, spec := range []domain.CreateVPNSpec{
		{ProtocolOptions: nil},
		{ProtocolOptions: opts},
		{ProtocolOptions: &opts},
		{ProtocolOptions: (*shadowsocks.CreateOptions)(nil)},
	} {
		if _, err := adapter.BuildProtocolData(ctx, spec, "vpn-ss", protocol.BuildModePreview); err != nil {
			t.Fatalf("spec %#v: %v", spec.ProtocolOptions, err)
		}
	}
}

func TestBuildProtocolData_validateOptionsErrors(t *testing.T) {
	adapter := &shadowsocks.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		ProtocolOptions: shadowsocks.CreateOptions{Plugin: "bad-plugin", PluginOpts: "x"},
	}
	if _, err := adapter.BuildProtocolData(ctx, spec, "vpn-ss", protocol.BuildModePreview); err == nil {
		t.Fatal("expected unsupported plugin error")
	}
}

func TestBuildCreateProtocolData_provisionErrors(t *testing.T) {
	t.Run("server key rand", func(t *testing.T) {
		reset := shadowsocks.SetGenProvidersForTest(func() *shadowsocks.KeyGen {
			return &shadowsocks.KeyGen{RandRead: failReader{}}
		}, nil)
		defer reset()
		_, err := shadowsocks.BuildCreateProtocolDataForTest(shadowsocks.CreateOptions{}, protocol.BuildModeProvision)
		if err == nil || !strings.Contains(err.Error(), "generate shadowsocks server key") {
			t.Fatalf("expected server key error, got %v", err)
		}
	})
	t.Run("shadowtls password rand", func(t *testing.T) {
		reset := shadowsocks.SetGenProvidersForTest(nil, func() *shadowsocks.OptionsGen {
			return &shadowsocks.OptionsGen{RandRead: failReader{}}
		})
		defer reset()
		_, err := shadowsocks.BuildCreateProtocolDataForTest(shadowsocks.CreateOptions{
			ShadowTLS: true, ListenPort: 443,
		}, protocol.BuildModeProvision)
		if err == nil || !strings.Contains(err.Error(), "generate shadowtls password") {
			t.Fatalf("expected shadowtls password error, got %v", err)
		}
	})
	t.Run("backend port rand", func(t *testing.T) {
		call := 0
		reset := shadowsocks.SetGenProvidersForTest(nil, func() *shadowsocks.OptionsGen {
			call++
			if call == 1 {
				return &shadowsocks.OptionsGen{}
			}
			return &shadowsocks.OptionsGen{RandRead: failReader{}}
		})
		defer reset()
		_, err := shadowsocks.BuildCreateProtocolDataForTest(shadowsocks.CreateOptions{
			ShadowTLS: true, ListenPort: 443,
		}, protocol.BuildModeProvision)
		if err == nil || !strings.Contains(err.Error(), "generate backend port") {
			t.Fatalf("expected backend port error, got %v", err)
		}
	})
}

func TestNeedsInitialClient(t *testing.T) {
	if !(&shadowsocks.Adapter{}).NeedsInitialClient(domain.VPNConfig{}) {
		t.Fatal("expected true")
	}
}
