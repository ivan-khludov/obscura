package vmess_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/protocol/testutil"
	"github.com/ivan-khludov/obscura/internal/protocol/vmess"
)

func TestBuildProtocolData_NoTLSPreview(t *testing.T) {
	adapter := &vmess.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		Protocol: domain.ProtocolVMess,
		ProtocolOptions: vmess.CreateOptions{
			NoTLS: true,
		},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-vmess", protocol.BuildModePreview)
	if err != nil {
		t.Fatal(err)
	}
	data, err := vmess.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !data.TLSDisabled {
		t.Fatal("expected TLSDisabled in no-tls mode")
	}
}

func TestBuildProtocolData_ProvisionUsesProvidedTLSPaths(t *testing.T) {
	adapter := &vmess.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		Protocol: domain.ProtocolVMess,
		ProtocolOptions: vmess.CreateOptions{
			ServerName: "example.com",
			CertPath:   "/tmp/vmess.crt",
			KeyPath:    "/tmp/vmess.key",
		},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-vmess", protocol.BuildModeProvision)
	if err != nil {
		t.Fatal(err)
	}
	data, err := vmess.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if data.CertPath != "/tmp/vmess.crt" || data.KeyPath != "/tmp/vmess.key" {
		t.Fatalf("unexpected tls paths: %#v", data)
	}
	if len(ctx.CertPaths) != 2 || ctx.ManifestSaves == 0 {
		t.Fatalf("expected manifest cert paths to be recorded, got %v saves=%d", ctx.CertPaths, ctx.ManifestSaves)
	}
}

func TestBuildProtocolData_unknownMode(t *testing.T) {
	adapter := &vmess.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	_, err := adapter.BuildProtocolData(ctx, domain.CreateVPNSpec{}, "tag", protocol.BuildMode(99))
	if err == nil || !strings.Contains(err.Error(), "unknown build mode") {
		t.Fatalf("expected unknown mode error, got %v", err)
	}
}

func TestBuildProtocolData_invalidOptionsType(t *testing.T) {
	adapter := &vmess.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	_, err := adapter.BuildProtocolData(ctx, domain.CreateVPNSpec{ProtocolOptions: "bad"}, "tag", protocol.BuildModePreview)
	if err == nil || !strings.Contains(err.Error(), "unexpected type") {
		t.Fatalf("expected type error, got %v", err)
	}
}

func TestBuildProtocolData_createOptionsFromSpec(t *testing.T) {
	adapter := &vmess.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	opts := vmess.CreateOptions{ServerName: "example.com", CertPath: "/a.crt", KeyPath: "/a.key"}
	for _, spec := range []domain.CreateVPNSpec{
		{ProtocolOptions: nil},
		{ProtocolOptions: opts},
		{ProtocolOptions: &opts},
		{ProtocolOptions: (*vmess.CreateOptions)(nil)},
	} {
		if _, err := adapter.BuildProtocolData(ctx, spec, "vpn-vmess", protocol.BuildModePreview); err != nil {
			t.Fatalf("spec %#v: %v", spec.ProtocolOptions, err)
		}
	}
}

func TestBuildCreateProtocolData_defaults(t *testing.T) {
	data, err := vmess.BuildCreateProtocolDataForTest("host.example.com", vmess.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if data.ServerName != "host.example.com" {
		t.Fatalf("server name = %q", data.ServerName)
	}
	if len(data.ALPN) != len(vmess.DefaultALPN) {
		t.Fatalf("alpn = %#v", data.ALPN)
	}
}

func TestBuildCreateProtocolData_noTLS(t *testing.T) {
	data, err := vmess.BuildCreateProtocolDataForTest("host.example.com", vmess.CreateOptions{NoTLS: true})
	if err != nil {
		t.Fatal(err)
	}
	if !data.TLSDisabled || data.ServerName != "" {
		t.Fatalf("no tls data = %#v", data)
	}
}

func TestApplyPreviewTLS_branches(t *testing.T) {
	t.Run("reality", func(t *testing.T) {
		data := vmess.ProtocolData{ServerName: "example.com"}
		vmess.ApplyPreviewTLSForTest(&data, vmess.CreateOptions{Reality: true})
		if data.RealityPrivateKey == "" || data.RealityHandshakeServer != "example.com" {
			t.Fatalf("reality preview: %#v", data)
		}
	})
	t.Run("acme ech", func(t *testing.T) {
		data := vmess.ProtocolData{
			ServerName: "example.com",
			ACME:       &vmess.ACMEOptions{Domains: []string{"example.com"}},
		}
		vmess.ApplyPreviewTLSForTest(&data, vmess.CreateOptions{ECH: true})
		if !data.ECHEnabled || data.ECHKeyPath == "" {
			t.Fatalf("acme ech preview: %#v", data)
		}
	})
	t.Run("cert paths ech", func(t *testing.T) {
		data := vmess.ProtocolData{CertPath: "/a.crt", KeyPath: "/a.key"}
		vmess.ApplyPreviewTLSForTest(&data, vmess.CreateOptions{ECH: true})
		if !data.ECHEnabled || data.ECHKeyPath == "" {
			t.Fatalf("cert ech preview: %#v", data)
		}
	})
	t.Run("default ech", func(t *testing.T) {
		data := vmess.ProtocolData{ServerName: "example.com"}
		vmess.ApplyPreviewTLSForTest(&data, vmess.CreateOptions{ECH: true})
		if data.CertPath == "" || !data.ECHEnabled {
			t.Fatalf("default ech preview: %#v", data)
		}
	})
}

func TestApplyTransport_allModes(t *testing.T) {
	transports := []struct {
		name string
		opts vmess.CreateOptions
		typ  string
	}{
		{"tcp", vmess.CreateOptions{Transport: "tcp"}, ""},
		{"empty", vmess.CreateOptions{}, ""},
		{"quic", vmess.CreateOptions{Transport: "quic"}, "quic"},
		{"http", vmess.CreateOptions{Transport: "http", TransportHost: "h", TransportPath: "/p"}, "http"},
		{"http hosts", vmess.CreateOptions{Transport: "http", TransportHosts: []string{"h"}, TransportPath: "/p"}, "http"},
		{"ws", vmess.CreateOptions{Transport: "ws", TransportPath: "/ws", WSMaxEarlyData: 1, WSEarlyDataHeaderName: "X"}, "ws"},
		{"grpc", vmess.CreateOptions{Transport: "grpc", TransportServiceName: "svc", GRPCPermitWithoutStream: true}, "grpc"},
		{"httpupgrade", vmess.CreateOptions{Transport: "httpupgrade", TransportHost: "h", TransportPath: "/up"}, "httpupgrade"},
	}
	for _, tc := range transports {
		t.Run(tc.name, func(t *testing.T) {
			data := vmess.ProtocolData{}
			if err := vmess.ApplyTransportForTest(&data, tc.opts); err != nil {
				t.Fatal(err)
			}
			if data.TransportType != tc.typ {
				t.Fatalf("transport type = %q, want %q", data.TransportType, tc.typ)
			}
		})
	}
}

func TestApplyTransport_errors(t *testing.T) {
	data := vmess.ProtocolData{}
	err := vmess.ApplyTransportForTest(&data, vmess.CreateOptions{TransportHeadersJSON: `{`})
	if err == nil || !strings.Contains(err.Error(), "parse transport headers json") {
		t.Fatalf("headers error = %v", err)
	}
	err = vmess.ApplyTransportForTest(&data, vmess.CreateOptions{Transport: "bad"})
	if err == nil || !strings.Contains(err.Error(), "unsupported vmess transport") {
		t.Fatalf("transport error = %v", err)
	}
}

func TestBuildCreateProtocolData_httpupgradeALPN(t *testing.T) {
	data, err := vmess.BuildCreateProtocolDataForTest("host.example.com", vmess.CreateOptions{
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
	_, err := vmess.BuildCreateProtocolDataForTest("host", vmess.CreateOptions{
		FallbackForALPNJSON: `{`,
	})
	if err == nil || !strings.Contains(err.Error(), "parse fallback_for_alpn json") {
		t.Fatalf("fallback json error = %v", err)
	}
}

func TestBuildProtocolData_validateOptionsError(t *testing.T) {
	adapter := &vmess.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		ProtocolOptions: vmess.CreateOptions{
			CertPath: "/a.crt", KeyPath: "/a.key",
			MultiplexBrutal: true,
		},
	}
	_, err := adapter.BuildProtocolData(ctx, spec, "vpn-vmess", protocol.BuildModePreview)
	if err == nil || !strings.Contains(err.Error(), "multiplex brutal") {
		t.Fatalf("expected validation error, got %v", err)
	}
}

func TestBuildCreateProtocolData_realityFingerprint(t *testing.T) {
	data, err := vmess.BuildCreateProtocolDataForTest("host", vmess.CreateOptions{
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

func TestResolveRealityUTLSFingerprint(t *testing.T) {
	fp, err := vmess.ResolveRealityUTLSFingerprintForTest(false, "")
	if err != nil || fp != "" {
		t.Fatalf("ResolveRealityUTLSFingerprint() = %q, %v", fp, err)
	}
	fp, err = vmess.ResolveRealityUTLSFingerprintForTest(true, "firefox")
	if err != nil || fp != "firefox" {
		t.Fatalf("ResolveRealityUTLSFingerprint() = %q, %v", fp, err)
	}
	_, err = vmess.ResolveRealityUTLSFingerprintForTest(false, "chrome")
	if err == nil || !strings.Contains(err.Error(), "reality fingerprint requires reality") {
		t.Fatalf("fp without reality error = %v", err)
	}
	_, err = vmess.ResolveRealityUTLSFingerprintForTest(true, "bad")
	if err == nil {
		t.Fatal("expected invalid fingerprint error")
	}
}

func TestSetupTLS_remainingBranches(t *testing.T) {
	restore := vmess.SetTLSGenFactoryForTest(func() *vmess.TLSGen {
		return &vmess.TLSGen{
			RunCommand: func(_ string, args ...string) ([]byte, error) {
				for _, a := range args {
					if a == "ech-keypair" {
						return []byte(sampleECHOutput), nil
					}
				}
				return []byte(sampleRealityOutput), nil
			},
		}
	})
	defer restore()

	t.Run("acme only", func(t *testing.T) {
		ctx := testutil.NewBuildContext(t.TempDir())
		data := vmess.ProtocolData{ACME: &vmess.ACMEOptions{Domains: []string{"example.com"}, Email: "a@b.c"}}
		if err := vmess.SetupTLSForTest(ctx, &data, "tag", vmess.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("provided cert no ech", func(t *testing.T) {
		ctx := testutil.NewBuildContext(t.TempDir())
		data := vmess.ProtocolData{CertPath: "/a.crt", KeyPath: "/a.key"}
		if err := vmess.SetupTLSForTest(ctx, &data, "tag", vmess.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("reality default handshake", func(t *testing.T) {
		ctx := testutil.NewBuildContext(t.TempDir())
		data := vmess.ProtocolData{RealityEnabled: true, RealityPrivateKey: "k", RealityShortIDs: []string{"ab"}, ServerName: "example.com"}
		if err := vmess.SetupTLSForTest(ctx, &data, "tag", vmess.CreateOptions{Reality: true}); err != nil {
			t.Fatal(err)
		}
		if data.RealityHandshakeServer != "example.com" {
			t.Fatalf("handshake server = %q", data.RealityHandshakeServer)
		}
	})
	t.Run("short id rand error", func(t *testing.T) {
		restore := vmess.SetTLSGenFactoryForTest(func() *vmess.TLSGen {
			return &vmess.TLSGen{RandRead: failReader{}}
		})
		defer restore()
		ctx := testutil.NewBuildContext(t.TempDir())
		data := vmess.ProtocolData{RealityEnabled: true, RealityPrivateKey: "k", ServerName: "example.com"}
		err := vmess.SetupTLSForTest(ctx, &data, "tag", vmess.CreateOptions{Reality: true})
		if err == nil || !strings.Contains(err.Error(), "generate reality short_id") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestBuildCreateProtocolData_acme(t *testing.T) {
	data, err := vmess.BuildCreateProtocolDataForTest("host", vmess.CreateOptions{
		ACMEDomains: []string{"example.com"}, ACMEEmail: "a@b.c",
	})
	if err != nil || data.ACME == nil {
		t.Fatalf("acme data = %#v, %v", data, err)
	}
}

func TestBuildCreateProtocolData_fallbackJSONValid(t *testing.T) {
	valid, err := vmess.BuildCreateProtocolDataForTest("host", vmess.CreateOptions{
		FallbackForALPNJSON: `{"h2":{"server":"127.0.0.1","server_port":8080}}`,
	})
	if err != nil || len(valid.FallbackForALPN) == 0 {
		t.Fatalf("valid fallback = %#v, %v", valid, err)
	}
}

func TestEchServerName(t *testing.T) {
	if vmess.EchServerNameForTest("sn", nil) != "sn" {
		t.Fatal("expected server name")
	}
	if vmess.EchServerNameForTest("", []string{"acme.example.com"}) != "acme.example.com" {
		t.Fatal("expected acme domain")
	}
	if vmess.EchServerNameForTest("", nil) != "localhost" {
		t.Fatal("expected localhost default")
	}
}

func TestNeedsInitialClient(t *testing.T) {
	if !(&vmess.Adapter{}).NeedsInitialClient(domain.VPNConfig{}) {
		t.Fatal("expected true")
	}
}

func TestSetupTLS_provisionBranches(t *testing.T) {
	restore := vlessTLSMock(t)
	defer restore()

	t.Run("reality generate", func(t *testing.T) {
		ctx := testutil.NewBuildContext(t.TempDir())
		data := vmess.ProtocolData{RealityEnabled: true, ServerName: "example.com"}
		if err := vmess.SetupTLSForTest(ctx, &data, "tag", vmess.CreateOptions{Reality: true}); err != nil {
			t.Fatal(err)
		}
		if data.RealityPrivateKey != "priv" || len(data.RealityShortIDs) == 0 {
			t.Fatalf("reality setup: %#v", data)
		}
	})
	t.Run("acme ech", func(t *testing.T) {
		ctx := testutil.NewBuildContext(t.TempDir())
		if err := os.MkdirAll(filepath.Join(ctx.DataDir(), "certs"), 0o755); err != nil {
			t.Fatal(err)
		}
		data := vmess.ProtocolData{
			ServerName: "example.com",
			ACME:       &vmess.ACMEOptions{Domains: []string{"example.com"}},
		}
		if err := vmess.SetupTLSForTest(ctx, &data, "tag", vmess.CreateOptions{ECH: true}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("self signed", func(t *testing.T) {
		ctx := testutil.NewBuildContext(t.TempDir())
		data := vmess.ProtocolData{ServerName: "example.com"}
		if err := vmess.SetupTLSForTest(ctx, &data, "tag", vmess.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		if data.CertPath == "" {
			t.Fatalf("self signed: %#v", data)
		}
	})
}

func vlessTLSMock(t *testing.T) func() {
	t.Helper()
	return vmess.SetTLSGenFactoryForTest(func() *vmess.TLSGen {
		return &vmess.TLSGen{
			RunCommand: func(_ string, args ...string) ([]byte, error) {
				for _, a := range args {
					if a == "ech-keypair" {
						return []byte(sampleECHOutput), nil
					}
				}
				return []byte(sampleRealityOutput), nil
			},
		}
	})
}

func TestSetupTLS_errors(t *testing.T) {
	restore := vmess.SetTLSGenFactoryForTest(func() *vmess.TLSGen {
		return &vmess.TLSGen{
			RunCommand: func(string, ...string) ([]byte, error) {
				return nil, errors.New("exec failed")
			},
		}
	})
	defer restore()
	ctx := testutil.NewBuildContext(t.TempDir())
	data := vmess.ProtocolData{RealityEnabled: true, ServerName: "example.com"}
	err := vmess.SetupTLSForTest(ctx, &data, "tag", vmess.CreateOptions{Reality: true})
	if err == nil || !strings.Contains(err.Error(), "generate reality keypair") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetupECH_existingPath(t *testing.T) {
	ctx := testutil.NewBuildContext(t.TempDir())
	data := vmess.ProtocolData{ECHKeyPath: "/existing-ech.key"}
	if err := vmess.SetupECHForTest(ctx, &data, "tag"); err != nil {
		t.Fatal(err)
	}
}

func TestBuildProtocolData_buildCreateProtocolDataError(t *testing.T) {
	adapter := &vmess.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		ProtocolOptions: vmess.CreateOptions{Transport: "bad"},
	}
	_, err := adapter.BuildProtocolData(ctx, spec, "vpn-vmess", protocol.BuildModePreview)
	if err == nil || !strings.Contains(err.Error(), "unsupported vmess transport") {
		t.Fatalf("expected transport error, got %v", err)
	}
}

func TestBuildProtocolData_provisionSetupTLSError(t *testing.T) {
	restore := vmess.SetTLSGenFactoryForTest(func() *vmess.TLSGen {
		return &vmess.TLSGen{
			RunCommand: func(string, ...string) ([]byte, error) {
				return nil, errors.New("exec failed")
			},
		}
	})
	defer restore()
	adapter := &vmess.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{ProtocolOptions: vmess.CreateOptions{Reality: true, ServerName: "example.com"}}
	_, err := adapter.BuildProtocolData(ctx, spec, "vpn-vmess", protocol.BuildModeProvision)
	if err == nil || !strings.Contains(err.Error(), "generate reality keypair") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildCreateProtocolData_buildErrors(t *testing.T) {
	_, err := vmess.BuildCreateProtocolDataForTest("host", vmess.CreateOptions{RealityUTLSFingerprint: "firefox"})
	if err == nil || !strings.Contains(err.Error(), "reality fingerprint requires reality") {
		t.Fatalf("fingerprint error = %v", err)
	}
}

func TestBuildCreateProtocolData_defaultRealityFingerprint(t *testing.T) {
	data, err := vmess.BuildCreateProtocolDataForTest("host", vmess.CreateOptions{
		Reality: true, RealityPrivateKey: "k", RealityShortIDs: []string{"ab"}, RealityHandshake: "x.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if data.RealityUTLSFingerprint == "" {
		t.Fatal("expected default reality fingerprint")
	}
}

func TestSetupTLS_saveManifestError(t *testing.T) {
	ctx := newErrBuildContext(t.TempDir(), true)
	data := vmess.ProtocolData{CertPath: "/a.crt", KeyPath: "/a.key"}
	err := vmess.SetupTLSForTest(ctx, &data, "tag", vmess.CreateOptions{})
	if err == nil || !strings.Contains(err.Error(), "manifest save failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetupTLS_providedCertWithECH(t *testing.T) {
	restore := vmess.SetTLSGenFactoryForTest(func() *vmess.TLSGen {
		return &vmess.TLSGen{
			RunCommand: func(_ string, args ...string) ([]byte, error) {
				for _, a := range args {
					if a == "ech-keypair" {
						return []byte(sampleECHOutput), nil
					}
				}
				return []byte(sampleRealityOutput), nil
			},
		}
	})
	defer restore()
	ctx := testutil.NewBuildContext(t.TempDir())
	if err := os.MkdirAll(filepath.Join(ctx.DataDir(), "certs"), 0o755); err != nil {
		t.Fatal(err)
	}
	data := vmess.ProtocolData{CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com"}
	if err := vmess.SetupTLSForTest(ctx, &data, "tag", vmess.CreateOptions{ECH: true}); err != nil {
		t.Fatal(err)
	}
	if !data.ECHEnabled || data.ECHKeyPath == "" {
		t.Fatalf("expected ech setup: %#v", data)
	}
}

func TestSetupTLS_selfSignedGenerateError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "certs"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	data := vmess.ProtocolData{ServerName: "example.com"}
	ctx := testutil.NewBuildContext(dir)
	err := vmess.SetupTLSForTest(ctx, &data, "tag", vmess.CreateOptions{})
	if err == nil || !strings.Contains(err.Error(), "generate tls certificate") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetupTLS_selfSignedSaveManifestError(t *testing.T) {
	data := vmess.ProtocolData{ServerName: "example.com"}
	ctx := newErrBuildContext(t.TempDir(), true)
	err := vmess.SetupTLSForTest(ctx, &data, "tag", vmess.CreateOptions{})
	if err == nil || !strings.Contains(err.Error(), "manifest save failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetupTLS_selfSignedWithECH(t *testing.T) {
	restore := vmess.SetTLSGenFactoryForTest(func() *vmess.TLSGen {
		return &vmess.TLSGen{
			RunCommand: func(_ string, args ...string) ([]byte, error) {
				for _, a := range args {
					if a == "ech-keypair" {
						return []byte(sampleECHOutput), nil
					}
				}
				return []byte(sampleRealityOutput), nil
			},
		}
	})
	defer restore()
	ctx := testutil.NewBuildContext(t.TempDir())
	data := vmess.ProtocolData{ServerName: "example.com"}
	if err := vmess.SetupTLSForTest(ctx, &data, "tag", vmess.CreateOptions{ECH: true}); err != nil {
		t.Fatal(err)
	}
	if !data.ECHEnabled || data.ECHKeyPath == "" {
		t.Fatalf("expected ech after self-signed: %#v", data)
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
	data := vmess.ProtocolData{RealityEnabled: true, ServerName: "example.com"}
	if err := vmess.SetupTLSForTest(ctx, &data, "tag", vmess.CreateOptions{Reality: true}); err != nil {
		t.Fatal(err)
	}
	if data.RealityPrivateKey == "" {
		t.Fatalf("reality setup: %#v", data)
	}
}

func TestSetupECH_generateError(t *testing.T) {
	restore := vmess.SetTLSGenFactoryForTest(func() *vmess.TLSGen {
		return &vmess.TLSGen{
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
	data := vmess.ProtocolData{ServerName: "example.com", CertPath: "/a.crt", KeyPath: "/a.key"}
	err := vmess.SetupECHForTest(ctx, &data, "tag")
	if err == nil || !strings.Contains(err.Error(), "generate ech keypair") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildProtocolData_provisionSelfSigned(t *testing.T) {
	restore := vmess.SetTLSGenFactoryForTest(func() *vmess.TLSGen { return &vmess.TLSGen{} })
	defer restore()
	adapter := &vmess.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{ProtocolOptions: vmess.CreateOptions{ServerName: "example.com"}}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-vmess", protocol.BuildModeProvision)
	if err != nil {
		t.Fatal(err)
	}
	data, err := vmess.ParseProtocolData(raw)
	if err != nil || data.CertPath == "" {
		t.Fatalf("provision data = %#v, %v", data, err)
	}
}
