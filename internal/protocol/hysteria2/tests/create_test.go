package hysteria2_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/protocol/hysteria2"
	"github.com/ivan-khludov/obscura/internal/protocol/testutil"
)

func TestBuildProtocolData_previewAppliesTLSPlaceholders(t *testing.T) {
	adapter := &hysteria2.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		Protocol: domain.ProtocolHysteria2,
		ProtocolOptions: hysteria2.CreateOptions{
			ServerName: "example.com",
		},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-hy2", protocol.BuildModePreview)
	if err != nil {
		t.Fatal(err)
	}
	data, err := hysteria2.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if data.CertPath != "/preview/obscura.crt" || data.KeyPath != "/preview/obscura.key" {
		t.Fatalf("unexpected preview tls placeholders: %#v", data)
	}
}

func TestBuildProtocolData_previewObfsAuto(t *testing.T) {
	adapter := &hysteria2.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		ProtocolOptions: hysteria2.CreateOptions{ObfsPassword: "auto"},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-hy2", protocol.BuildModePreview)
	if err != nil {
		t.Fatal(err)
	}
	data, err := hysteria2.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if data.ObfsPassword != "preview-obfs-password" {
		t.Fatalf("obfs = %q", data.ObfsPassword)
	}
}

func TestBuildProtocolData_previewECH(t *testing.T) {
	adapter := &hysteria2.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		ProtocolOptions: hysteria2.CreateOptions{ECH: true},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-hy2", protocol.BuildModePreview)
	if err != nil {
		t.Fatal(err)
	}
	data, err := hysteria2.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !data.ECHEnabled || data.ECHKeyPath != "/preview/obscura-ech.key" {
		t.Fatalf("ech = %#v", data)
	}
}

func TestBuildProtocolData_previewACMEWithECH(t *testing.T) {
	adapter := &hysteria2.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		ProtocolOptions: hysteria2.CreateOptions{
			ACMEDomains: []string{"example.com"},
			ACMEEmail:   "a@b.com",
			ECH:         true,
		},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-hy2", protocol.BuildModePreview)
	if err != nil {
		t.Fatal(err)
	}
	data, err := hysteria2.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if data.ECHKeyPath != "/preview/obscura-ech.key" {
		t.Fatalf("ech path = %q", data.ECHKeyPath)
	}
}

func TestBuildProtocolData_previewExistingCertsWithECH(t *testing.T) {
	adapter := &hysteria2.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		ProtocolOptions: hysteria2.CreateOptions{
			CertPath: "/tmp/c.crt", KeyPath: "/tmp/c.key", ECH: true,
		},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-hy2", protocol.BuildModePreview)
	if err != nil {
		t.Fatal(err)
	}
	data, err := hysteria2.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if data.CertPath != "/tmp/c.crt" || data.ECHKeyPath != "/preview/obscura-ech.key" {
		t.Fatalf("data = %#v", data)
	}
}

func TestBuildProtocolData_ProvisionUsesProvidedTLSPaths(t *testing.T) {
	adapter := &hysteria2.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		Protocol: domain.ProtocolHysteria2,
		ProtocolOptions: hysteria2.CreateOptions{
			ServerName: "example.com",
			CertPath:   "/tmp/hy2.crt",
			KeyPath:    "/tmp/hy2.key",
		},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-hy2", protocol.BuildModeProvision)
	if err != nil {
		t.Fatal(err)
	}
	data, err := hysteria2.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if data.CertPath != "/tmp/hy2.crt" || data.KeyPath != "/tmp/hy2.key" {
		t.Fatalf("unexpected tls paths: %#v", data)
	}
	if ctx.ManifestSaves != 1 {
		t.Fatalf("manifest saves = %d", ctx.ManifestSaves)
	}
}

func TestBuildProtocolData_provisionObfsAuto(t *testing.T) {
	adapter := &hysteria2.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		ProtocolOptions: hysteria2.CreateOptions{
			CertPath: "/a.crt", KeyPath: "/a.key", ObfsPassword: "auto",
		},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-hy2", protocol.BuildModeProvision)
	if err != nil {
		t.Fatal(err)
	}
	data, err := hysteria2.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if data.ObfsPassword != "test-password" {
		t.Fatalf("obfs = %q", data.ObfsPassword)
	}
}

func TestBuildProtocolData_provisionGeneratesSelfSigned(t *testing.T) {
	adapter := &hysteria2.Adapter{}
	dir := t.TempDir()
	ctx := testutil.NewBuildContext(dir)
	spec := domain.CreateVPNSpec{
		ProtocolOptions: hysteria2.CreateOptions{ServerName: "example.com"},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-hy2", protocol.BuildModeProvision)
	if err != nil {
		t.Fatal(err)
	}
	data, err := hysteria2.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	wantCert := filepath.Join(dir, "certs", "vpn-hy2.crt")
	if data.CertPath != wantCert {
		t.Fatalf("cert path = %q, want %q", data.CertPath, wantCert)
	}
	if _, err := os.Stat(wantCert); err != nil {
		t.Fatal(err)
	}
}

func TestBuildProtocolData_provisionACME(t *testing.T) {
	adapter := &hysteria2.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		ProtocolOptions: hysteria2.CreateOptions{
			ACMEDomains: []string{"example.com"},
			ACMEEmail:   "a@b.com",
		},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-hy2", protocol.BuildModeProvision)
	if err != nil {
		t.Fatal(err)
	}
	data, err := hysteria2.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if data.ACME == nil || len(data.ACME.Domains) != 1 {
		t.Fatalf("acme = %#v", data.ACME)
	}
}

func TestBuildProtocolData_provisionECH(t *testing.T) {
	restore := hysteria2.SetTLSGenFactoryForTest(func() *hysteria2.TLSGen {
		return &hysteria2.TLSGen{
			RunCommand: func(string, ...string) ([]byte, error) {
				return []byte(sampleECHOutput), nil
			},
		}
	})
	defer restore()

	adapter := &hysteria2.Adapter{}
	dir := t.TempDir()
	ctx := testutil.NewBuildContext(dir)
	spec := domain.CreateVPNSpec{
		ProtocolOptions: hysteria2.CreateOptions{
			CertPath: "/a.crt", KeyPath: "/a.key", ECH: true,
		},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-hy2", protocol.BuildModeProvision)
	if err != nil {
		t.Fatal(err)
	}
	data, err := hysteria2.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	wantECH := filepath.Join(dir, "certs", "vpn-hy2-ech.key")
	if data.ECHKeyPath != wantECH {
		t.Fatalf("ech path = %q", data.ECHKeyPath)
	}
}

func TestBuildProtocolData_unknownMode(t *testing.T) {
	adapter := &hysteria2.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	_, err := adapter.BuildProtocolData(ctx, domain.CreateVPNSpec{}, "vpn-hy2", protocol.BuildMode(99))
	if err == nil || !strings.Contains(err.Error(), "unknown build mode") {
		t.Fatalf("expected mode error, got %v", err)
	}
}

func TestBuildProtocolData_invalidOptionsType(t *testing.T) {
	adapter := &hysteria2.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{ProtocolOptions: "bad"}
	_, err := adapter.BuildProtocolData(ctx, spec, "vpn-hy2", protocol.BuildModePreview)
	if err == nil || !strings.Contains(err.Error(), "unexpected type") {
		t.Fatalf("expected type error, got %v", err)
	}
}

func TestBuildProtocolData_createOptionsFromSpec(t *testing.T) {
	adapter := &hysteria2.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	opts := hysteria2.CreateOptions{ServerName: "example.com", CertPath: "/a.crt", KeyPath: "/a.key"}
	for _, spec := range []domain.CreateVPNSpec{
		{ProtocolOptions: nil},
		{ProtocolOptions: opts},
		{ProtocolOptions: &opts},
		{ProtocolOptions: (*hysteria2.CreateOptions)(nil)},
	} {
		if _, err := adapter.BuildProtocolData(ctx, spec, "vpn-hy2", protocol.BuildModePreview); err != nil {
			t.Fatalf("spec %#v: %v", spec.ProtocolOptions, err)
		}
	}
}

func TestBuildCreateProtocolData_allBranches(t *testing.T) {
	data, err := hysteria2.BuildCreateProtocolDataForTest("host.example.com", hysteria2.CreateOptions{
		ALPN:                    []string{"h3"},
		ACMEDomains:             []string{"example.com"},
		ACMEEmail:               "a@b.com",
		MasqueradeType:          hysteria2.MasqueradeTypeString,
		MasqueradeStatusCode:    404,
		MasqueradeHeadersJSON:   `{"X-Test":"1"}`,
		MasqueradeContent:       "gone",
		HTTP2IdleTimeout:        "30s",
		RealmServerURL:          "https://realm.example.com",
		RealmID:                 "realm-1",
		RealmSTUNServers:        []string{"stun:1"},
		RealmSTUNDomainResolver: "local",
		RealmHTTPClientJSON:     `{"timeout":"5s"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if data.ServerName != "host.example.com" {
		t.Fatalf("server name = %q", data.ServerName)
	}
	if data.ACME == nil || data.Masquerade == nil || data.HTTP2 == nil || data.Realm == nil {
		t.Fatalf("data = %#v", data)
	}
	if string(data.Realm.STUNDomainResolver) != `"local"` {
		t.Fatalf("resolver = %s", data.Realm.STUNDomainResolver)
	}
}

func TestBuildCreateProtocolData_defaults(t *testing.T) {
	data, err := hysteria2.BuildCreateProtocolDataForTest("example.com", hysteria2.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if data.ServerName != "example.com" || len(data.ALPN) != 1 || data.ALPN[0] != "h3" {
		t.Fatalf("defaults = %#v", data)
	}
}

func TestBuildMasqueradeObject_errors(t *testing.T) {
	_, err := hysteria2.BuildMasqueradeObjectForTest(hysteria2.CreateOptions{
		MasqueradeType:        hysteria2.MasqueradeTypeString,
		MasqueradeHeadersJSON: `{`,
	})
	if err == nil || !strings.Contains(err.Error(), "parse masquerade headers json") {
		t.Fatalf("expected headers error, got %v", err)
	}
}

func TestBuildMasqueradeObject_types(t *testing.T) {
	file, err := hysteria2.BuildMasqueradeObjectForTest(hysteria2.CreateOptions{
		MasqueradeType: hysteria2.MasqueradeTypeFile, MasqueradeDirectory: "/www",
	})
	if err != nil || file.Directory != "/www" {
		t.Fatalf("file masq = %#v, %v", file, err)
	}
	proxy, err := hysteria2.BuildMasqueradeObjectForTest(hysteria2.CreateOptions{
		MasqueradeType: hysteria2.MasqueradeTypeProxy, MasqueradeProxyURL: "http://x", MasqueradeRewriteHost: true,
	})
	if err != nil || proxy.URL != "http://x" || !proxy.RewriteHost {
		t.Fatalf("proxy masq = %#v, %v", proxy, err)
	}
}

func TestApplyPreviewTLS_branches(t *testing.T) {
	t.Run("acme no ech", func(t *testing.T) {
		data := hysteria2.ProtocolData{ACME: &hysteria2.ACMEOptions{Domains: []string{"example.com"}}}
		hysteria2.ApplyPreviewTLSForTest(&data, hysteria2.CreateOptions{})
		if data.ECHKeyPath != "" {
			t.Fatalf("ech = %#v", data)
		}
	})
	t.Run("existing certs no ech", func(t *testing.T) {
		data := hysteria2.ProtocolData{CertPath: "/a.crt", KeyPath: "/a.key"}
		hysteria2.ApplyPreviewTLSForTest(&data, hysteria2.CreateOptions{})
		if data.ECHKeyPath != "" {
			t.Fatalf("ech = %#v", data)
		}
	})
}

func TestSetupTLS_errors(t *testing.T) {
	t.Run("save manifest on provided certs", func(t *testing.T) {
		data := hysteria2.ProtocolData{CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com"}
		ctx := newManifestErrContext(t.TempDir(), errSaveManifest())
		err := hysteria2.SetupTLSForTest(ctx, &data, "vpn-hy2", hysteria2.CreateOptions{})
		if err == nil || !strings.Contains(err.Error(), "save manifest failed") {
			t.Fatalf("expected save error, got %v", err)
		}
	})
	t.Run("generate cert failure", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "certs"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		data := hysteria2.ProtocolData{ServerName: "example.com"}
		ctx := testutil.NewBuildContext(dir)
		err := hysteria2.SetupTLSForTest(ctx, &data, "vpn-hy2", hysteria2.CreateOptions{})
		if err == nil || !strings.Contains(err.Error(), "generate tls certificate") {
			t.Fatalf("expected cert error, got %v", err)
		}
	})
	t.Run("save manifest after generate", func(t *testing.T) {
		data := hysteria2.ProtocolData{ServerName: "example.com"}
		ctx := newManifestErrContext(t.TempDir(), errSaveManifest())
		err := hysteria2.SetupTLSForTest(ctx, &data, "vpn-hy2", hysteria2.CreateOptions{})
		if err == nil || !strings.Contains(err.Error(), "save manifest failed") {
			t.Fatalf("expected save error, got %v", err)
		}
	})
}

func TestSetupECH_branches(t *testing.T) {
	t.Run("existing key path", func(t *testing.T) {
		data := hysteria2.ProtocolData{ECHKeyPath: "/existing.key"}
		ctx := testutil.NewBuildContext(t.TempDir())
		if err := hysteria2.SetupECHForTest(ctx, &data, "vpn-hy2"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("generate failure", func(t *testing.T) {
		restore := hysteria2.SetTLSGenFactoryForTest(func() *hysteria2.TLSGen {
			return &hysteria2.TLSGen{
				RunCommand: func(string, ...string) ([]byte, error) {
					return nil, errors.New("exec failed")
				},
			}
		})
		defer restore()
		data := hysteria2.ProtocolData{ServerName: "example.com"}
		ctx := testutil.NewBuildContext(t.TempDir())
		err := hysteria2.SetupECHForTest(ctx, &data, "vpn-hy2")
		if err == nil || !strings.Contains(err.Error(), "generate ech keypair") {
			t.Fatalf("expected ech error, got %v", err)
		}
	})
	t.Run("save manifest failure", func(t *testing.T) {
		restore := hysteria2.SetTLSGenFactoryForTest(func() *hysteria2.TLSGen {
			return &hysteria2.TLSGen{
				RunCommand: func(string, ...string) ([]byte, error) {
					return []byte(sampleECHOutput), nil
				},
			}
		})
		defer restore()
		data := hysteria2.ProtocolData{ServerName: "example.com"}
		ctx := newManifestErrContext(t.TempDir(), errSaveManifest())
		err := hysteria2.SetupECHForTest(ctx, &data, "vpn-hy2")
		if err == nil || !strings.Contains(err.Error(), "save manifest failed") {
			t.Fatalf("expected save error, got %v", err)
		}
	})
}

func TestEchServerName(t *testing.T) {
	if got := hysteria2.EchServerNameForTest("sn", nil); got != "sn" {
		t.Fatalf("got %q", got)
	}
	if got := hysteria2.EchServerNameForTest("", []string{"acme.example.com"}); got != "acme.example.com" {
		t.Fatalf("got %q", got)
	}
	if got := hysteria2.EchServerNameForTest("", nil); got != "localhost" {
		t.Fatalf("got %q", got)
	}
}

func TestSetupTLS_acmeWithECH(t *testing.T) {
	restore := hysteria2.SetTLSGenFactoryForTest(func() *hysteria2.TLSGen {
		return &hysteria2.TLSGen{
			RunCommand: func(string, ...string) ([]byte, error) {
				return []byte(sampleECHOutput), nil
			},
		}
	})
	defer restore()
	data := hysteria2.ProtocolData{
		ACME: &hysteria2.ACMEOptions{Domains: []string{"example.com"}, Email: "a@b.com"},
	}
	ctx := testutil.NewBuildContext(t.TempDir())
	if err := hysteria2.SetupTLSForTest(ctx, &data, "vpn-hy2", hysteria2.CreateOptions{ECH: true}); err != nil {
		t.Fatal(err)
	}
}

func TestSetupTLS_providedCertsWithECH(t *testing.T) {
	restore := hysteria2.SetTLSGenFactoryForTest(func() *hysteria2.TLSGen {
		return &hysteria2.TLSGen{
			RunCommand: func(string, ...string) ([]byte, error) {
				return []byte(sampleECHOutput), nil
			},
		}
	})
	defer restore()
	data := hysteria2.ProtocolData{CertPath: "/a.crt", KeyPath: "/a.key", ServerName: "example.com"}
	ctx := testutil.NewBuildContext(t.TempDir())
	if err := hysteria2.SetupTLSForTest(ctx, &data, "vpn-hy2", hysteria2.CreateOptions{ECH: true}); err != nil {
		t.Fatal(err)
	}
}

func TestBuildProtocolData_validateOptionsError(t *testing.T) {
	adapter := &hysteria2.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		ProtocolOptions: hysteria2.CreateOptions{BBRProfile: "invalid"},
	}
	_, err := adapter.BuildProtocolData(ctx, spec, "vpn-hy2", protocol.BuildModePreview)
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestBuildProtocolData_buildCreateProtocolDataError(t *testing.T) {
	adapter := &hysteria2.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		ProtocolOptions: hysteria2.CreateOptions{
			MasqueradeType:        hysteria2.MasqueradeTypeString,
			MasqueradeHeadersJSON: `{`,
		},
	}
	_, err := adapter.BuildProtocolData(ctx, spec, "vpn-hy2", protocol.BuildModePreview)
	if err == nil || !strings.Contains(err.Error(), "parse masquerade headers json") {
		t.Fatalf("expected masquerade error, got %v", err)
	}
}

func TestBuildProtocolData_provisionObfsPasswordError(t *testing.T) {
	adapter := &hysteria2.Adapter{}
	ctx := newErrPasswordContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		ProtocolOptions: hysteria2.CreateOptions{
			CertPath: "/a.crt", KeyPath: "/a.key", ObfsPassword: "auto",
		},
	}
	_, err := adapter.BuildProtocolData(ctx, spec, "vpn-hy2", protocol.BuildModeProvision)
	if err == nil || !strings.Contains(err.Error(), "generate obfs password") {
		t.Fatalf("expected password error, got %v", err)
	}
}

func TestBuildProtocolData_provisionSetupTLSError(t *testing.T) {
	adapter := &hysteria2.Adapter{}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "certs"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := testutil.NewBuildContext(dir)
	spec := domain.CreateVPNSpec{
		ProtocolOptions: hysteria2.CreateOptions{ServerName: "example.com"},
	}
	_, err := adapter.BuildProtocolData(ctx, spec, "vpn-hy2", protocol.BuildModeProvision)
	if err == nil || !strings.Contains(err.Error(), "generate tls certificate") {
		t.Fatalf("expected tls error, got %v", err)
	}
}

func TestSetupTLS_selfSignedWithECH(t *testing.T) {
	restore := hysteria2.SetTLSGenFactoryForTest(func() *hysteria2.TLSGen {
		return &hysteria2.TLSGen{
			RunCommand: func(string, ...string) ([]byte, error) {
				return []byte(sampleECHOutput), nil
			},
		}
	})
	defer restore()
	data := hysteria2.ProtocolData{ServerName: "example.com"}
	ctx := testutil.NewBuildContext(t.TempDir())
	if err := hysteria2.SetupTLSForTest(ctx, &data, "vpn-hy2", hysteria2.CreateOptions{ECH: true}); err != nil {
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
	data := hysteria2.ProtocolData{ServerName: "example.com"}
	ctx := testutil.NewBuildContext(dir)
	err := hysteria2.SetupECHForTest(ctx, &data, "vpn-hy2")
	if err == nil || !strings.Contains(err.Error(), "create ech key dir") {
		t.Fatalf("expected mkdir error, got %v", err)
	}
}
