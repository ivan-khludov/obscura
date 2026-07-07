package tuic_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/protocol/testutil"
	"github.com/ivan-khludov/obscura/internal/protocol/tuic"
)

func TestBuildProtocolData_PreviewAppliesTLSPlaceholders(t *testing.T) {
	adapter := &tuic.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		Protocol: domain.ProtocolTUIC,
		ProtocolOptions: tuic.CreateOptions{
			ServerName: "example.com",
		},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-tuic", protocol.BuildModePreview)
	if err != nil {
		t.Fatal(err)
	}
	data, err := tuic.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if data.CertPath != "/preview/obscura.crt" || data.KeyPath != "/preview/obscura.key" {
		t.Fatalf("unexpected preview tls placeholders: %#v", data)
	}
}

func TestBuildProtocolData_previewECH(t *testing.T) {
	adapter := &tuic.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		ProtocolOptions: tuic.CreateOptions{ECH: true},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-tuic", protocol.BuildModePreview)
	if err != nil {
		t.Fatal(err)
	}
	data, err := tuic.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !data.ECHEnabled || data.ECHKeyPath != "/preview/obscura-ech.key" {
		t.Fatalf("ech = %#v", data)
	}
}

func TestBuildProtocolData_previewACMEWithECH(t *testing.T) {
	adapter := &tuic.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		ProtocolOptions: tuic.CreateOptions{
			ACMEDomains: []string{"example.com"},
			ACMEEmail:   "a@b.com",
			ECH:         true,
		},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-tuic", protocol.BuildModePreview)
	if err != nil {
		t.Fatal(err)
	}
	data, err := tuic.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if data.ECHKeyPath != "/preview/obscura-ech.key" {
		t.Fatalf("ech path = %q", data.ECHKeyPath)
	}
}

func TestBuildProtocolData_previewExistingCertsWithECH(t *testing.T) {
	adapter := &tuic.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		ProtocolOptions: tuic.CreateOptions{
			CertPath: "/tmp/c.crt", KeyPath: "/tmp/c.key", ECH: true,
		},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-tuic", protocol.BuildModePreview)
	if err != nil {
		t.Fatal(err)
	}
	data, err := tuic.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if data.CertPath != "/tmp/c.crt" || data.ECHKeyPath != "/preview/obscura-ech.key" {
		t.Fatalf("data = %#v", data)
	}
}

func TestBuildProtocolData_ProvisionUsesProvidedTLSPaths(t *testing.T) {
	adapter := &tuic.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		Protocol: domain.ProtocolTUIC,
		ProtocolOptions: tuic.CreateOptions{
			ServerName: "example.com",
			CertPath:   "/tmp/tuic.crt",
			KeyPath:    "/tmp/tuic.key",
		},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-tuic", protocol.BuildModeProvision)
	if err != nil {
		t.Fatal(err)
	}
	data, err := tuic.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if data.CertPath != "/tmp/tuic.crt" || data.KeyPath != "/tmp/tuic.key" {
		t.Fatalf("unexpected tls paths: %#v", data)
	}
	if ctx.ManifestSaves != 1 {
		t.Fatalf("manifest saves = %d", ctx.ManifestSaves)
	}
}

func TestBuildProtocolData_provisionGeneratesSelfSigned(t *testing.T) {
	adapter := &tuic.Adapter{}
	dir := t.TempDir()
	ctx := testutil.NewBuildContext(dir)
	spec := domain.CreateVPNSpec{
		ProtocolOptions: tuic.CreateOptions{ServerName: "example.com"},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-tuic", protocol.BuildModeProvision)
	if err != nil {
		t.Fatal(err)
	}
	data, err := tuic.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	wantCert := filepath.Join(dir, "certs", "vpn-tuic.crt")
	if data.CertPath != wantCert {
		t.Fatalf("cert path = %q, want %q", data.CertPath, wantCert)
	}
	if _, err := os.Stat(wantCert); err != nil {
		t.Fatal(err)
	}
}

func TestBuildProtocolData_provisionACME(t *testing.T) {
	adapter := &tuic.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		ProtocolOptions: tuic.CreateOptions{
			ACMEDomains: []string{"example.com"},
			ACMEEmail:   "a@b.com",
		},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-tuic", protocol.BuildModeProvision)
	if err != nil {
		t.Fatal(err)
	}
	data, err := tuic.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if data.ACME == nil || len(data.ACME.Domains) != 1 {
		t.Fatalf("acme = %#v", data.ACME)
	}
}

func TestBuildProtocolData_provisionECH(t *testing.T) {
	restore := tuic.SetTLSGenFactoryForTest(func() *tuic.TLSGen {
		return &tuic.TLSGen{
			RunCommand: func(string, ...string) ([]byte, error) {
				return []byte(sampleECHOutput), nil
			},
		}
	})
	defer restore()

	adapter := &tuic.Adapter{}
	dir := t.TempDir()
	ctx := testutil.NewBuildContext(dir)
	spec := domain.CreateVPNSpec{
		ProtocolOptions: tuic.CreateOptions{
			CertPath: "/a.crt", KeyPath: "/a.key", ECH: true,
		},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-tuic", protocol.BuildModeProvision)
	if err != nil {
		t.Fatal(err)
	}
	data, err := tuic.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	wantECH := filepath.Join(dir, "certs", "vpn-tuic-ech.key")
	if data.ECHKeyPath != wantECH {
		t.Fatalf("ech path = %q", data.ECHKeyPath)
	}
}

func TestBuildProtocolData_unknownMode(t *testing.T) {
	adapter := &tuic.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	_, err := adapter.BuildProtocolData(ctx, domain.CreateVPNSpec{}, "vpn-tuic", protocol.BuildMode(99))
	if err == nil || !strings.Contains(err.Error(), "unknown build mode") {
		t.Fatalf("expected mode error, got %v", err)
	}
}

func TestBuildProtocolData_invalidOptionsType(t *testing.T) {
	adapter := &tuic.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{ProtocolOptions: "bad"}
	_, err := adapter.BuildProtocolData(ctx, spec, "vpn-tuic", protocol.BuildModePreview)
	if err == nil || !strings.Contains(err.Error(), "unexpected type") {
		t.Fatalf("expected type error, got %v", err)
	}
}

func TestBuildProtocolData_createOptionsFromSpec(t *testing.T) {
	adapter := &tuic.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	opts := tuic.CreateOptions{ServerName: "example.com", CertPath: "/a.crt", KeyPath: "/a.key"}
	for _, spec := range []domain.CreateVPNSpec{
		{ProtocolOptions: nil},
		{ProtocolOptions: opts},
		{ProtocolOptions: &opts},
		{ProtocolOptions: (*tuic.CreateOptions)(nil)},
	} {
		if _, err := adapter.BuildProtocolData(ctx, spec, "vpn-tuic", protocol.BuildModePreview); err != nil {
			t.Fatalf("spec %#v: %v", spec.ProtocolOptions, err)
		}
	}
}

func TestBuildCreateProtocolData_allBranches(t *testing.T) {
	data := tuic.BuildCreateProtocolDataForTest("host.example.com", tuic.CreateOptions{
		ALPN:                      []string{"h3"},
		ACMEDomains:               []string{"example.com"},
		ACMEEmail:                 "a@b.com",
		CongestionControl:         tuic.CongestionBBR,
		AuthTimeout:               "10s",
		ZeroRTTHandshake:          true,
		Heartbeat:                 "3s",
		HTTP2IdleTimeout:          "30s",
		HTTP2MaxConcurrentStreams: 100,
		InitialPacketSize:         1200,
		DisablePathMTUDiscovery:   true,
	})
	if data.ServerName != "host.example.com" {
		t.Fatalf("server name = %q", data.ServerName)
	}
	if data.ACME == nil || data.HTTP2 == nil {
		t.Fatalf("data = %#v", data)
	}
	if data.CongestionControl != tuic.CongestionBBR {
		t.Fatalf("cc = %q", data.CongestionControl)
	}
}

func TestBuildCreateProtocolData_defaults(t *testing.T) {
	data := tuic.BuildCreateProtocolDataForTest("example.com", tuic.CreateOptions{})
	if data.ServerName != "example.com" || len(data.ALPN) != 1 || data.ALPN[0] != "h3" {
		t.Fatalf("defaults = %#v", data)
	}
}

func TestApplyPreviewTLS_branches(t *testing.T) {
	t.Run("acme no ech", func(t *testing.T) {
		data := tuic.ProtocolData{ACME: &tuic.ACMEOptions{Domains: []string{"example.com"}}}
		tuic.ApplyPreviewTLSForTest(&data, tuic.CreateOptions{})
		if data.ECHKeyPath != "" {
			t.Fatalf("ech = %#v", data)
		}
	})
	t.Run("existing certs no ech", func(t *testing.T) {
		data := tuic.ProtocolData{CertPath: "/a.crt", KeyPath: "/a.key"}
		tuic.ApplyPreviewTLSForTest(&data, tuic.CreateOptions{})
		if data.ECHKeyPath != "" {
			t.Fatalf("ech = %#v", data)
		}
	})
}

func TestSetupTLS_errors(t *testing.T) {
	t.Run("save manifest on provided certs", func(t *testing.T) {
		data := tuic.ProtocolData{CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com"}
		ctx := newManifestErrContext(t.TempDir(), errSaveManifest())
		err := tuic.SetupTLSForTest(ctx, &data, "vpn-tuic", tuic.CreateOptions{})
		if err == nil || !strings.Contains(err.Error(), "save manifest failed") {
			t.Fatalf("expected save error, got %v", err)
		}
	})
	t.Run("generate cert failure", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "certs"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		data := tuic.ProtocolData{ServerName: "example.com"}
		ctx := testutil.NewBuildContext(dir)
		err := tuic.SetupTLSForTest(ctx, &data, "vpn-tuic", tuic.CreateOptions{})
		if err == nil || !strings.Contains(err.Error(), "generate tls certificate") {
			t.Fatalf("expected cert error, got %v", err)
		}
	})
	t.Run("save manifest after generate", func(t *testing.T) {
		data := tuic.ProtocolData{ServerName: "example.com"}
		ctx := newManifestErrContext(t.TempDir(), errSaveManifest())
		err := tuic.SetupTLSForTest(ctx, &data, "vpn-tuic", tuic.CreateOptions{})
		if err == nil || !strings.Contains(err.Error(), "save manifest failed") {
			t.Fatalf("expected save error, got %v", err)
		}
	})
}

func TestSetupECH_branches(t *testing.T) {
	t.Run("existing key path", func(t *testing.T) {
		data := tuic.ProtocolData{ECHKeyPath: "/existing.key"}
		ctx := testutil.NewBuildContext(t.TempDir())
		if err := tuic.SetupECHForTest(ctx, &data, "vpn-tuic"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("generate failure", func(t *testing.T) {
		restore := tuic.SetTLSGenFactoryForTest(func() *tuic.TLSGen {
			return &tuic.TLSGen{
				RunCommand: func(string, ...string) ([]byte, error) {
					return nil, errors.New("exec failed")
				},
			}
		})
		defer restore()
		data := tuic.ProtocolData{ServerName: "example.com"}
		ctx := testutil.NewBuildContext(t.TempDir())
		err := tuic.SetupECHForTest(ctx, &data, "vpn-tuic")
		if err == nil || !strings.Contains(err.Error(), "generate ech keypair") {
			t.Fatalf("expected ech error, got %v", err)
		}
	})
	t.Run("save manifest failure", func(t *testing.T) {
		restore := tuic.SetTLSGenFactoryForTest(func() *tuic.TLSGen {
			return &tuic.TLSGen{
				RunCommand: func(string, ...string) ([]byte, error) {
					return []byte(sampleECHOutput), nil
				},
			}
		})
		defer restore()
		data := tuic.ProtocolData{ServerName: "example.com"}
		ctx := newManifestErrContext(t.TempDir(), errSaveManifest())
		err := tuic.SetupECHForTest(ctx, &data, "vpn-tuic")
		if err == nil || !strings.Contains(err.Error(), "save manifest failed") {
			t.Fatalf("expected save error, got %v", err)
		}
	})
}

func TestEchServerName(t *testing.T) {
	if got := tuic.EchServerNameForTest("sn", nil); got != "sn" {
		t.Fatalf("got %q", got)
	}
	if got := tuic.EchServerNameForTest("", []string{"acme.example.com"}); got != "acme.example.com" {
		t.Fatalf("got %q", got)
	}
	if got := tuic.EchServerNameForTest("", nil); got != "localhost" {
		t.Fatalf("got %q", got)
	}
}

func TestSetupTLS_acmeWithECH(t *testing.T) {
	restore := tuic.SetTLSGenFactoryForTest(func() *tuic.TLSGen {
		return &tuic.TLSGen{
			RunCommand: func(string, ...string) ([]byte, error) {
				return []byte(sampleECHOutput), nil
			},
		}
	})
	defer restore()
	data := tuic.ProtocolData{
		ACME: &tuic.ACMEOptions{Domains: []string{"example.com"}, Email: "a@b.com"},
	}
	ctx := testutil.NewBuildContext(t.TempDir())
	if err := tuic.SetupTLSForTest(ctx, &data, "vpn-tuic", tuic.CreateOptions{ECH: true}); err != nil {
		t.Fatal(err)
	}
}

func TestSetupTLS_providedCertsWithECH(t *testing.T) {
	restore := tuic.SetTLSGenFactoryForTest(func() *tuic.TLSGen {
		return &tuic.TLSGen{
			RunCommand: func(string, ...string) ([]byte, error) {
				return []byte(sampleECHOutput), nil
			},
		}
	})
	defer restore()
	data := tuic.ProtocolData{CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com"}
	ctx := testutil.NewBuildContext(t.TempDir())
	if err := tuic.SetupTLSForTest(ctx, &data, "vpn-tuic", tuic.CreateOptions{ECH: true}); err != nil {
		t.Fatal(err)
	}
}

func TestBuildProtocolData_validateOptionsError(t *testing.T) {
	adapter := &tuic.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		ProtocolOptions: tuic.CreateOptions{CongestionControl: "invalid"},
	}
	_, err := adapter.BuildProtocolData(ctx, spec, "vpn-tuic", protocol.BuildModePreview)
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestNeedsInitialClient(t *testing.T) {
	if !(&tuic.Adapter{}).NeedsInitialClient(domain.VPNConfig{}) {
		t.Fatal("expected true")
	}
}

func TestBuildProtocolData_provisionSetupTLSError(t *testing.T) {
	adapter := &tuic.Adapter{}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "certs"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := testutil.NewBuildContext(dir)
	spec := domain.CreateVPNSpec{
		ProtocolOptions: tuic.CreateOptions{ServerName: "example.com"},
	}
	_, err := adapter.BuildProtocolData(ctx, spec, "vpn-tuic", protocol.BuildModeProvision)
	if err == nil || !strings.Contains(err.Error(), "generate tls certificate") {
		t.Fatalf("expected tls error, got %v", err)
	}
}

func TestSetupTLS_selfSignedWithECH(t *testing.T) {
	restore := tuic.SetTLSGenFactoryForTest(func() *tuic.TLSGen {
		return &tuic.TLSGen{
			RunCommand: func(string, ...string) ([]byte, error) {
				return []byte(sampleECHOutput), nil
			},
		}
	})
	defer restore()
	data := tuic.ProtocolData{ServerName: "example.com"}
	ctx := testutil.NewBuildContext(t.TempDir())
	if err := tuic.SetupTLSForTest(ctx, &data, "vpn-tuic", tuic.CreateOptions{ECH: true}); err != nil {
		t.Fatal(err)
	}
	if data.ECHKeyPath == "" {
		t.Fatal("expected ech key path")
	}
}

func TestSetupECH_mkdirError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "certs"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	data := tuic.ProtocolData{ServerName: "example.com"}
	ctx := testutil.NewBuildContext(dir)
	err := tuic.SetupECHForTest(ctx, &data, "vpn-tuic")
	if err == nil || !strings.Contains(err.Error(), "create ech key dir") {
		t.Fatalf("expected mkdir error, got %v", err)
	}
}
