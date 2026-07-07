package vless_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/protocol/testutil"
	"github.com/ivan-khludov/obscura/internal/protocol/vless"
)

func TestBuildProtocolData_PreviewAppliesTLSPlaceholders(t *testing.T) {
	adapter := &vless.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		Protocol: domain.ProtocolVLESS,
		ProtocolOptions: vless.CreateOptions{
			ServerName: "example.com",
		},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-vless", protocol.BuildModePreview)
	if err != nil {
		t.Fatal(err)
	}
	data, err := vless.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if data.CertPath != "/preview/obscura.crt" || data.KeyPath != "/preview/obscura.key" {
		t.Fatalf("unexpected preview tls placeholders: %#v", data)
	}
}

func TestBuildProtocolData_ProvisionUsesProvidedTLSPaths(t *testing.T) {
	adapter := &vless.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		Protocol: domain.ProtocolVLESS,
		ProtocolOptions: vless.CreateOptions{
			ServerName: "example.com",
			CertPath:   "/tmp/vless.crt",
			KeyPath:    "/tmp/vless.key",
		},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-vless", protocol.BuildModeProvision)
	if err != nil {
		t.Fatal(err)
	}
	data, err := vless.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if data.CertPath != "/tmp/vless.crt" || data.KeyPath != "/tmp/vless.key" {
		t.Fatalf("unexpected tls paths: %#v", data)
	}
}

func TestBuildProtocolData_unknownMode(t *testing.T) {
	adapter := &vless.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	_, err := adapter.BuildProtocolData(ctx, domain.CreateVPNSpec{}, "tag", protocol.BuildMode(99))
	if err == nil || !strings.Contains(err.Error(), "unknown build mode") {
		t.Fatalf("expected unknown mode error, got %v", err)
	}
}

func TestBuildProtocolData_invalidOptionsType(t *testing.T) {
	adapter := &vless.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	_, err := adapter.BuildProtocolData(ctx, domain.CreateVPNSpec{ProtocolOptions: "bad"}, "tag", protocol.BuildModePreview)
	if err == nil || !strings.Contains(err.Error(), "unexpected type") {
		t.Fatalf("expected type error, got %v", err)
	}
}

func TestBuildProtocolData_createOptionsFromSpec(t *testing.T) {
	adapter := &vless.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	opts := vless.CreateOptions{ServerName: "example.com", CertPath: "/a.crt", KeyPath: "/a.key"}
	for _, spec := range []domain.CreateVPNSpec{
		{ProtocolOptions: nil},
		{ProtocolOptions: opts},
		{ProtocolOptions: &opts},
		{ProtocolOptions: (*vless.CreateOptions)(nil)},
	} {
		if _, err := adapter.BuildProtocolData(ctx, spec, "vpn-vless", protocol.BuildModePreview); err != nil {
			t.Fatalf("spec %#v: %v", spec.ProtocolOptions, err)
		}
	}
}

func TestBuildCreateProtocolData_defaults(t *testing.T) {
	data, err := vless.BuildCreateProtocolDataForTest("host.example.com", vless.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if data.ServerName != "host.example.com" {
		t.Fatalf("server name = %q", data.ServerName)
	}
	if len(data.ALPN) != len(vless.DefaultALPN) {
		t.Fatalf("alpn = %#v", data.ALPN)
	}
}

func TestApplyPreviewTLS_branches(t *testing.T) {
	t.Run("reality", func(t *testing.T) {
		data := vless.ProtocolData{ServerName: "example.com"}
		vless.ApplyPreviewTLSForTest(&data, vless.CreateOptions{Reality: true})
		if data.RealityPrivateKey == "" || data.RealityHandshakeServer != "example.com" {
			t.Fatalf("reality preview: %#v", data)
		}
	})
	t.Run("acme ech", func(t *testing.T) {
		data := vless.ProtocolData{
			ServerName: "example.com",
			ACME:       &vless.ACMEOptions{Domains: []string{"example.com"}},
		}
		vless.ApplyPreviewTLSForTest(&data, vless.CreateOptions{ECH: true})
		if !data.ECHEnabled || data.ECHKeyPath == "" {
			t.Fatalf("acme ech preview: %#v", data)
		}
	})
	t.Run("cert paths ech", func(t *testing.T) {
		data := vless.ProtocolData{CertPath: "/a.crt", KeyPath: "/a.key"}
		vless.ApplyPreviewTLSForTest(&data, vless.CreateOptions{ECH: true})
		if !data.ECHEnabled || data.ECHKeyPath == "" {
			t.Fatalf("cert ech preview: %#v", data)
		}
	})
	t.Run("default ech", func(t *testing.T) {
		data := vless.ProtocolData{ServerName: "example.com"}
		vless.ApplyPreviewTLSForTest(&data, vless.CreateOptions{ECH: true})
		if data.CertPath == "" || !data.ECHEnabled {
			t.Fatalf("default ech preview: %#v", data)
		}
	})
}

func TestApplyTransport_allModes(t *testing.T) {
	transports := []struct {
		name string
		opts vless.CreateOptions
		typ  string
	}{
		{"tcp", vless.CreateOptions{Transport: "tcp"}, ""},
		{"empty", vless.CreateOptions{}, ""},
		{"quic", vless.CreateOptions{Transport: "quic"}, "quic"},
		{"http", vless.CreateOptions{Transport: "http", TransportHost: "h", TransportPath: "/p"}, "http"},
		{"http hosts", vless.CreateOptions{Transport: "http", TransportHosts: []string{"h"}, TransportPath: "/p"}, "http"},
		{"ws", vless.CreateOptions{Transport: "ws", TransportPath: "/ws", WSMaxEarlyData: 1, WSEarlyDataHeaderName: "X"}, "ws"},
		{"grpc", vless.CreateOptions{Transport: "grpc", TransportServiceName: "svc", GRPCPermitWithoutStream: true}, "grpc"},
		{"httpupgrade", vless.CreateOptions{Transport: "httpupgrade", TransportHost: "h", TransportPath: "/up"}, "httpupgrade"},
	}
	for _, tc := range transports {
		t.Run(tc.name, func(t *testing.T) {
			data := vless.ProtocolData{}
			if err := vless.ApplyTransportForTest(&data, tc.opts); err != nil {
				t.Fatal(err)
			}
			if data.TransportType != tc.typ {
				t.Fatalf("transport type = %q, want %q", data.TransportType, tc.typ)
			}
		})
	}
}

func TestApplyTransport_errors(t *testing.T) {
	data := vless.ProtocolData{}
	err := vless.ApplyTransportForTest(&data, vless.CreateOptions{TransportHeadersJSON: `{`})
	if err == nil || !strings.Contains(err.Error(), "parse transport headers json") {
		t.Fatalf("headers error = %v", err)
	}
	err = vless.ApplyTransportForTest(&data, vless.CreateOptions{Transport: "bad"})
	if err == nil || !strings.Contains(err.Error(), "unsupported vless transport") {
		t.Fatalf("transport error = %v", err)
	}
}

func TestBuildCreateProtocolData_httpupgradeALPN(t *testing.T) {
	data, err := vless.BuildCreateProtocolDataForTest("host.example.com", vless.CreateOptions{
		Transport: "httpupgrade", TransportPath: "/up",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(data.ALPN) != 1 || data.ALPN[0] != "http/1.1" {
		t.Fatalf("httpupgrade alpn = %#v, want [http/1.1]", data.ALPN)
	}
}

func TestBuildCreateProtocolData_fallbackJSON(t *testing.T) {
	_, err := vless.BuildCreateProtocolDataForTest("host", vless.CreateOptions{
		FallbackForALPNJSON: `{`,
	})
	if err == nil || !strings.Contains(err.Error(), "parse fallback_for_alpn json") {
		t.Fatalf("fallback json error = %v", err)
	}
	valid, err := vless.BuildCreateProtocolDataForTest("host", vless.CreateOptions{
		FallbackForALPNJSON: `{"h2":{"server":"127.0.0.1","server_port":8080}}`,
	})
	if err != nil || len(valid.FallbackForALPN) == 0 {
		t.Fatalf("valid fallback = %#v, %v", valid, err)
	}
}

func TestResolveRealityUTLSFingerprint(t *testing.T) {
	fp, err := vless.ResolveRealityUTLSFingerprintForTest(true, "")
	if err != nil || fp == "" {
		t.Fatalf("default fp = %q, %v", fp, err)
	}
	_, err = vless.ResolveRealityUTLSFingerprintForTest(false, "chrome")
	if err == nil || !strings.Contains(err.Error(), "reality fingerprint requires reality") {
		t.Fatalf("fp without reality error = %v", err)
	}
	_, err = vless.ResolveRealityUTLSFingerprintForTest(true, "bad")
	if err == nil {
		t.Fatal("expected invalid fingerprint error")
	}
}

func TestEchServerName(t *testing.T) {
	if vless.EchServerNameForTest("sn", nil) != "sn" {
		t.Fatal("expected server name")
	}
	if vless.EchServerNameForTest("", []string{"acme.example.com"}) != "acme.example.com" {
		t.Fatal("expected acme domain")
	}
	if vless.EchServerNameForTest("", nil) != "localhost" {
		t.Fatal("expected localhost default")
	}
}

func mockTLSRunCommand(args ...string) ([]byte, error) {
	for _, a := range args {
		if a == "ech-keypair" {
			return []byte(sampleECHOutput), nil
		}
	}
	return []byte(sampleRealityOutput), nil
}

func TestSetupTLS_provisionBranches(t *testing.T) {
	restore := vless.SetTLSGenFactoryForTest(func() *vless.TLSGen {
		return &vless.TLSGen{
			RunCommand: func(_ string, args ...string) ([]byte, error) {
				return mockTLSRunCommand(args...)
			},
		}
	})
	defer restore()

	t.Run("reality generate", func(t *testing.T) {
		ctx := testutil.NewBuildContext(t.TempDir())
		data := vless.ProtocolData{RealityEnabled: true, ServerName: "example.com"}
		if err := vless.SetupTLSForTest(ctx, &data, "tag", vless.CreateOptions{Reality: true}); err != nil {
			t.Fatal(err)
		}
		if data.RealityPrivateKey != "priv" || len(data.RealityShortIDs) == 0 {
			t.Fatalf("reality setup: %#v", data)
		}
	})
	t.Run("reality existing keys", func(t *testing.T) {
		ctx := testutil.NewBuildContext(t.TempDir())
		data := vless.ProtocolData{
			RealityEnabled: true, RealityPrivateKey: "existing", RealityShortIDs: []string{"abcd"},
			RealityHandshakeServer: "example.com",
		}
		if err := vless.SetupTLSForTest(ctx, &data, "tag", vless.CreateOptions{Reality: true}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("acme ech", func(t *testing.T) {
		ctx := testutil.NewBuildContext(t.TempDir())
		if err := os.MkdirAll(filepath.Join(ctx.DataDir(), "certs"), 0o755); err != nil {
			t.Fatal(err)
		}
		data := vless.ProtocolData{
			ServerName: "example.com",
			ACME:       &vless.ACMEOptions{Domains: []string{"example.com"}},
		}
		if err := vless.SetupTLSForTest(ctx, &data, "tag", vless.CreateOptions{ECH: true}); err != nil {
			t.Fatal(err)
		}
		if data.ECHKeyPath == "" {
			t.Fatal("expected ech key path")
		}
	})
	t.Run("acme only", func(t *testing.T) {
		ctx := testutil.NewBuildContext(t.TempDir())
		data := vless.ProtocolData{
			ACME: &vless.ACMEOptions{Domains: []string{"example.com"}, Email: "a@b.c"},
		}
		if err := vless.SetupTLSForTest(ctx, &data, "tag", vless.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("provided cert ech", func(t *testing.T) {
		ctx := testutil.NewBuildContext(t.TempDir())
		if err := os.MkdirAll(filepath.Join(ctx.DataDir(), "certs"), 0o755); err != nil {
			t.Fatal(err)
		}
		data := vless.ProtocolData{CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com"}
		if err := vless.SetupTLSForTest(ctx, &data, "tag", vless.CreateOptions{ECH: true}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("self signed", func(t *testing.T) {
		ctx := testutil.NewBuildContext(t.TempDir())
		data := vless.ProtocolData{ServerName: "example.com"}
		if err := vless.SetupTLSForTest(ctx, &data, "tag", vless.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		if data.CertPath == "" || ctx.ManifestSaves == 0 {
			t.Fatalf("self signed: %#v saves=%d", data, ctx.ManifestSaves)
		}
	})
}

func TestSetupTLS_errors(t *testing.T) {
	t.Run("reality keypair", func(t *testing.T) {
		restore := vless.SetTLSGenFactoryForTest(func() *vless.TLSGen {
			return &vless.TLSGen{
				RunCommand: func(string, ...string) ([]byte, error) {
					return nil, errors.New("exec failed")
				},
			}
		})
		defer restore()
		ctx := testutil.NewBuildContext(t.TempDir())
		data := vless.ProtocolData{RealityEnabled: true, ServerName: "example.com"}
		err := vless.SetupTLSForTest(ctx, &data, "tag", vless.CreateOptions{Reality: true})
		if err == nil || !strings.Contains(err.Error(), "generate reality keypair") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("short id rand", func(t *testing.T) {
		restore := vless.SetTLSGenFactoryForTest(func() *vless.TLSGen {
			return &vless.TLSGen{
				RunCommand: func(string, ...string) ([]byte, error) {
					return []byte(sampleRealityOutput), nil
				},
				RandRead: failReader{},
			}
		})
		defer restore()
		ctx := testutil.NewBuildContext(t.TempDir())
		data := vless.ProtocolData{RealityEnabled: true, RealityPrivateKey: "k", ServerName: "example.com"}
		err := vless.SetupTLSForTest(ctx, &data, "tag", vless.CreateOptions{Reality: true})
		if err == nil || !strings.Contains(err.Error(), "generate reality short_id") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestSetupECH_existingPath(t *testing.T) {
	ctx := testutil.NewBuildContext(t.TempDir())
	data := vless.ProtocolData{ECHKeyPath: "/existing-ech.key"}
	if err := vless.SetupECHForTest(ctx, &data, "tag"); err != nil {
		t.Fatal(err)
	}
}

func TestBuildProtocolData_provisionSelfSigned(t *testing.T) {
	restore := vless.SetTLSGenFactoryForTest(func() *vless.TLSGen { return &vless.TLSGen{} })
	defer restore()
	adapter := &vless.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{ProtocolOptions: vless.CreateOptions{ServerName: "example.com"}}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-vless", protocol.BuildModeProvision)
	if err != nil {
		t.Fatal(err)
	}
	data, err := vless.ParseProtocolData(raw)
	if err != nil || data.CertPath == "" {
		t.Fatalf("provision data = %#v, %v", data, err)
	}
}

func TestBuildProtocolData_validateOptionsError(t *testing.T) {
	adapter := &vless.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		ProtocolOptions: vless.CreateOptions{
			CertPath: "/a.crt", KeyPath: "/a.key",
			MultiplexBrutal: true,
		},
	}
	_, err := adapter.BuildProtocolData(ctx, spec, "vpn-vless", protocol.BuildModePreview)
	if err == nil || !strings.Contains(err.Error(), "multiplex brutal") {
		t.Fatalf("expected validation error, got %v", err)
	}
}

func TestBuildCreateProtocolData_realityFingerprint(t *testing.T) {
	data, err := vless.BuildCreateProtocolDataForTest("host", vless.CreateOptions{
		Reality: true, RealityUTLSFingerprint: "firefox",
		RealityPrivateKey: "k", RealityShortIDs: []string{"ab"}, RealityHandshake: "x.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if data.RealityUTLSFingerprint != "firefox" {
		t.Fatalf("fingerprint = %q", data.RealityUTLSFingerprint)
	}
}

func TestResolveRealityUTLSFingerprint_noRealityNoFP(t *testing.T) {
	fp, err := vless.ResolveRealityUTLSFingerprintForTest(false, "")
	if err != nil || fp != "" {
		t.Fatalf("ResolveRealityUTLSFingerprint() = %q, %v", fp, err)
	}
	fp, err = vless.ResolveRealityUTLSFingerprintForTest(true, "firefox")
	if err != nil || fp != "firefox" {
		t.Fatalf("ResolveRealityUTLSFingerprint() = %q, %v", fp, err)
	}
}

func TestSetupTLS_remainingBranches(t *testing.T) {
	restore := vless.SetTLSGenFactoryForTest(func() *vless.TLSGen {
		return &vless.TLSGen{
			RunCommand: func(_ string, args ...string) ([]byte, error) {
				return mockTLSRunCommand(args...)
			},
		}
	})
	defer restore()

	t.Run("reality default handshake", func(t *testing.T) {
		ctx := testutil.NewBuildContext(t.TempDir())
		data := vless.ProtocolData{RealityEnabled: true, RealityPrivateKey: "k", RealityShortIDs: []string{"ab"}, ServerName: "example.com"}
		if err := vless.SetupTLSForTest(ctx, &data, "tag", vless.CreateOptions{Reality: true}); err != nil {
			t.Fatal(err)
		}
		if data.RealityHandshakeServer != "example.com" {
			t.Fatalf("handshake server = %q", data.RealityHandshakeServer)
		}
	})
	t.Run("provided cert no ech", func(t *testing.T) {
		ctx := testutil.NewBuildContext(t.TempDir())
		data := vless.ProtocolData{CertPath: "/a.crt", KeyPath: "/a.key"}
		if err := vless.SetupTLSForTest(ctx, &data, "tag", vless.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		if len(ctx.CertPaths) != 2 {
			t.Fatalf("cert paths = %v", ctx.CertPaths)
		}
	})
	t.Run("self signed ech", func(t *testing.T) {
		ctx := testutil.NewBuildContext(t.TempDir())
		if err := os.MkdirAll(filepath.Join(ctx.DataDir(), "certs"), 0o755); err != nil {
			t.Fatal(err)
		}
		data := vless.ProtocolData{ServerName: "example.com"}
		if err := vless.SetupTLSForTest(ctx, &data, "tag", vless.CreateOptions{ECH: true}); err != nil {
			t.Fatal(err)
		}
		if data.ECHKeyPath == "" {
			t.Fatal("expected ech key path")
		}
	})
}

func TestBuildCreateProtocolData_acme(t *testing.T) {
	data, err := vless.BuildCreateProtocolDataForTest("host", vless.CreateOptions{
		ACMEDomains: []string{"example.com"}, ACMEEmail: "a@b.c",
	})
	if err != nil || data.ACME == nil {
		t.Fatalf("acme data = %#v, %v", data, err)
	}
}

func TestBuildCreateProtocolData_buildErrors(t *testing.T) {
	_, err := vless.BuildCreateProtocolDataForTest("host", vless.CreateOptions{Transport: "bad"})
	if err == nil || !strings.Contains(err.Error(), "unsupported vless transport") {
		t.Fatalf("transport error = %v", err)
	}
	_, err = vless.BuildCreateProtocolDataForTest("host", vless.CreateOptions{RealityUTLSFingerprint: "firefox"})
	if err == nil || !strings.Contains(err.Error(), "reality fingerprint requires reality") {
		t.Fatalf("fingerprint error = %v", err)
	}
}

func TestApplyPreviewTLS_existingECHKey(t *testing.T) {
	data := vless.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", ECHKeyPath: "/existing-ech.key",
	}
	vless.ApplyPreviewTLSForTest(&data, vless.CreateOptions{ECH: true})
	if data.ECHKeyPath != "/existing-ech.key" {
		t.Fatalf("expected existing ech key path, got %q", data.ECHKeyPath)
	}
}

func TestApplyTransport_headers(t *testing.T) {
	data := vless.ProtocolData{}
	if err := vless.ApplyTransportForTest(&data, vless.CreateOptions{
		Transport: "ws", TransportPath: "/ws", TransportHeadersJSON: `{"X-Test":"1"}`,
	}); err != nil {
		t.Fatal(err)
	}
	if data.TransportWS == nil || data.TransportWS.Headers["X-Test"] != "1" {
		t.Fatalf("headers = %#v", data.TransportWS)
	}
}

func TestSetupTLS_saveManifestError(t *testing.T) {
	ctx := newErrBuildContext(t.TempDir(), true)
	data := vless.ProtocolData{CertPath: "/a.crt", KeyPath: "/a.key"}
	err := vless.SetupTLSForTest(ctx, &data, "tag", vless.CreateOptions{})
	if err == nil || !strings.Contains(err.Error(), "manifest save failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetupECH_generateError(t *testing.T) {
	restore := vless.SetTLSGenFactoryForTest(func() *vless.TLSGen {
		return &vless.TLSGen{
			RunCommand: func(string, ...string) ([]byte, error) {
				return nil, errors.New("ech failed")
			},
		}
	})
	defer restore()
	ctx := testutil.NewBuildContext(t.TempDir())
	if err := os.MkdirAll(filepath.Join(ctx.DataDir(), "certs"), 0o755); err != nil {
		t.Fatal(err)
	}
	data := vless.ProtocolData{ServerName: "example.com", CertPath: "/a.crt", KeyPath: "/a.key"}
	err := vless.SetupECHForTest(ctx, &data, "tag")
	if err == nil || !strings.Contains(err.Error(), "generate ech keypair") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildProtocolData_provisionSetupTLSError(t *testing.T) {
	restore := vless.SetTLSGenFactoryForTest(func() *vless.TLSGen {
		return &vless.TLSGen{
			RunCommand: func(string, ...string) ([]byte, error) {
				return nil, errors.New("exec failed")
			},
		}
	})
	defer restore()
	adapter := &vless.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{ProtocolOptions: vless.CreateOptions{Reality: true, ServerName: "example.com"}}
	_, err := adapter.BuildProtocolData(ctx, spec, "vpn-vless", protocol.BuildModeProvision)
	if err == nil || !strings.Contains(err.Error(), "generate reality keypair") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildCreateProtocolData_fallbackJSONValid(t *testing.T) {
	valid, err := vless.BuildCreateProtocolDataForTest("host", vless.CreateOptions{
		FallbackForALPNJSON: `{"h2":{"server":"127.0.0.1","server_port":8080}}`,
	})
	if err != nil || len(valid.FallbackForALPN) == 0 {
		t.Fatalf("valid fallback = %#v, %v", valid, err)
	}
}

func TestNeedsInitialClient(t *testing.T) {
	if !(&vless.Adapter{}).NeedsInitialClient(domain.VPNConfig{}) {
		t.Fatal("expected true")
	}
}

func TestBuildProtocolData_buildCreateProtocolDataError(t *testing.T) {
	adapter := &vless.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		ProtocolOptions: vless.CreateOptions{Transport: "bad"},
	}
	_, err := adapter.BuildProtocolData(ctx, spec, "vpn-vless", protocol.BuildModePreview)
	if err == nil || !strings.Contains(err.Error(), "unsupported vless transport") {
		t.Fatalf("expected transport error, got %v", err)
	}
}

func TestSetupTLS_selfSignedGenerateError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "certs"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	data := vless.ProtocolData{ServerName: "example.com"}
	ctx := testutil.NewBuildContext(dir)
	err := vless.SetupTLSForTest(ctx, &data, "tag", vless.CreateOptions{})
	if err == nil || !strings.Contains(err.Error(), "generate tls certificate") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetupTLS_selfSignedSaveManifestError(t *testing.T) {
	data := vless.ProtocolData{ServerName: "example.com"}
	ctx := newErrBuildContext(t.TempDir(), true)
	err := vless.SetupTLSForTest(ctx, &data, "tag", vless.CreateOptions{})
	if err == nil || !strings.Contains(err.Error(), "manifest save failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetupTLS_realityDefaultFactory(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "sing-box")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s' '"+sampleRealityOutput+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx := testutil.NewBuildContext(t.TempDir())
	ctx.SingBoxPath = script
	data := vless.ProtocolData{RealityEnabled: true, ServerName: "example.com"}
	if err := vless.SetupTLSForTest(ctx, &data, "tag", vless.CreateOptions{Reality: true}); err != nil {
		t.Fatal(err)
	}
	if data.RealityPrivateKey == "" {
		t.Fatalf("reality setup: %#v", data)
	}
}
