package httpproxy_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/protocol/httpproxy"
	"github.com/ivan-khludov/obscura/internal/protocol/testutil"
)

type manifestFailCtx struct {
	*testutil.BuildContext
}

func (c *manifestFailCtx) SaveManifest() error {
	return errors.New("manifest save failed")
}

func TestBuildProtocolData_noTLS(t *testing.T) {
	adapter := &httpproxy.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	raw, err := adapter.BuildProtocolData(ctx, domain.CreateVPNSpec{}, "vpn-http", protocol.BuildModePreview)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "{}" {
		t.Fatalf("got %q", raw)
	}
}

func TestBuildProtocolData_HTTP(t *testing.T) {
	adapter := &httpproxy.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		Protocol:        domain.ProtocolHTTP,
		ProtocolOptions: httpproxy.CreateOptions{TLS: true},
	}

	previewRaw, err := adapter.BuildProtocolData(ctx, spec, "vpn-http", protocol.BuildModePreview)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	preview, err := httpproxy.ParseProtocolData(previewRaw)
	if err != nil {
		t.Fatalf("parse preview: %v", err)
	}
	if preview.CertPath != "/preview/obscura.crt" || preview.KeyPath != "/preview/obscura.key" {
		t.Fatalf("unexpected preview cert paths: %#v", preview)
	}

	provisionRaw, err := adapter.BuildProtocolData(ctx, spec, "vpn-http", protocol.BuildModeProvision)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	provision, err := httpproxy.ParseProtocolData(provisionRaw)
	if err != nil {
		t.Fatalf("parse provision: %v", err)
	}
	if !provision.TLS {
		t.Fatal("expected TLS enabled in provision mode")
	}
	if len(ctx.CertPaths) != 2 || ctx.ManifestSaves == 0 {
		t.Fatalf("expected cert paths and manifest save, got paths=%v saves=%d", ctx.CertPaths, ctx.ManifestSaves)
	}
	if _, err := os.Stat(filepath.Clean(provision.CertPath)); err != nil {
		t.Fatalf("expected generated cert file: %v", err)
	}
	if _, err := os.Stat(filepath.Clean(provision.KeyPath)); err != nil {
		t.Fatalf("expected generated key file: %v", err)
	}
}

func TestBuildProtocolData_errors(t *testing.T) {
	adapter := &httpproxy.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{ProtocolOptions: "bad"}
	_, err := adapter.BuildProtocolData(ctx, spec, "tag", protocol.BuildModePreview)
	if err == nil {
		t.Fatal("expected options type error")
	}
	_, err = adapter.BuildProtocolData(ctx, domain.CreateVPNSpec{ProtocolOptions: httpproxy.CreateOptions{TLS: true}}, "tag", protocol.BuildMode(99))
	if err == nil {
		t.Fatal("expected unknown mode error")
	}
	failCtx := &manifestFailCtx{BuildContext: testutil.NewBuildContext(t.TempDir())}
	_, err = adapter.BuildProtocolData(failCtx, domain.CreateVPNSpec{ProtocolOptions: httpproxy.CreateOptions{TLS: true}}, "tag", protocol.BuildModeProvision)
	if err == nil {
		t.Fatal("expected manifest save error")
	}
}

func TestBuildProtocolData_createOptionsFromSpec(t *testing.T) {
	adapter := &httpproxy.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	opts := httpproxy.CreateOptions{TLS: true}
	for _, spec := range []domain.CreateVPNSpec{
		{ProtocolOptions: nil},
		{ProtocolOptions: opts},
		{ProtocolOptions: &opts},
		{ProtocolOptions: (*httpproxy.CreateOptions)(nil)},
	} {
		if _, err := adapter.BuildProtocolData(ctx, spec, "tag", protocol.BuildModePreview); err != nil {
			t.Fatalf("spec %#v: %v", spec.ProtocolOptions, err)
		}
	}
}

func TestBuildProtocolData_certGenerationError(t *testing.T) {
	adapter := &httpproxy.Adapter{}
	f := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := testutil.NewBuildContext(f)
	spec := domain.CreateVPNSpec{ProtocolOptions: httpproxy.CreateOptions{TLS: true}}
	_, err := adapter.BuildProtocolData(ctx, spec, "vpn-http", protocol.BuildModeProvision)
	if err == nil || !strings.Contains(err.Error(), "generate tls certificate") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNeedsInitialClient(t *testing.T) {
	if !(&httpproxy.Adapter{}).NeedsInitialClient(domain.VPNConfig{}) {
		t.Fatal("expected true")
	}
}
