package trojan_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/protocol/testutil"
	"github.com/ivan-khludov/obscura/internal/protocol/trojan"
)

type manifestFailCtx struct {
	*testutil.BuildContext
}

func (c *manifestFailCtx) SaveManifest() error {
	return errors.New("manifest save failed")
}

func ensureCertsDir(t *testing.T, ctx *testutil.BuildContext) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(ctx.DataDir(), "certs"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestBuildProtocolData_PreviewAppliesTLSPlaceholders(t *testing.T) {
	adapter := &trojan.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		Protocol:        domain.ProtocolTrojan,
		ProtocolOptions: trojan.CreateOptions{ServerName: "example.com"},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-trojan", protocol.BuildModePreview)
	if err != nil {
		t.Fatal(err)
	}
	data, err := trojan.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if data.CertPath != "/preview/obscura.crt" || data.KeyPath != "/preview/obscura.key" {
		t.Fatalf("unexpected preview tls placeholders: %#v", data)
	}
}

func TestBuildProtocolData_ProvisionUsesProvidedTLSPaths(t *testing.T) {
	adapter := &trojan.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		Protocol: domain.ProtocolTrojan,
		ProtocolOptions: trojan.CreateOptions{
			ServerName: "example.com",
			CertPath:   "/tmp/trojan.crt",
			KeyPath:    "/tmp/trojan.key",
		},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-trojan", protocol.BuildModeProvision)
	if err != nil {
		t.Fatal(err)
	}
	data, err := trojan.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if data.CertPath != "/tmp/trojan.crt" || data.KeyPath != "/tmp/trojan.key" {
		t.Fatalf("unexpected tls paths: %#v", data)
	}
	if len(ctx.CertPaths) != 2 || ctx.ManifestSaves == 0 {
		t.Fatalf("expected manifest cert paths, got %v saves=%d", ctx.CertPaths, ctx.ManifestSaves)
	}
}

func TestBuildProtocolData_ProvisionGeneratesSelfSigned(t *testing.T) {
	adapter := &trojan.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		ProtocolOptions: trojan.CreateOptions{ServerName: "example.com"},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-trojan", protocol.BuildModeProvision)
	if err != nil {
		t.Fatal(err)
	}
	data, err := trojan.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Clean(data.CertPath)); err != nil {
		t.Fatalf("expected cert file: %v", err)
	}
	if _, err := os.Stat(filepath.Clean(data.KeyPath)); err != nil {
		t.Fatalf("expected key file: %v", err)
	}
}

func TestBuildProtocolData_previewReality(t *testing.T) {
	adapter := &trojan.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		ProtocolOptions: trojan.CreateOptions{
			ServerName: "example.com",
			Reality:    true,
		},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-trojan", protocol.BuildModePreview)
	if err != nil {
		t.Fatal(err)
	}
	data, err := trojan.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if data.RealityPrivateKey != "preview-reality-private-key" || data.RealityHandshakeServer != "example.com" {
		t.Fatalf("unexpected preview reality: %#v", data)
	}
	if len(data.RealityShortIDs) != 1 || data.RealityShortIDs[0] != "abcd" {
		t.Fatalf("unexpected short ids: %#v", data.RealityShortIDs)
	}
}

func TestBuildProtocolData_provisionReality(t *testing.T) {
	reset := trojan.SetTLSGenProviderForTest(func() *trojan.TLSGen {
		return &trojan.TLSGen{
			RunCommand: func(_ string, args ...string) ([]byte, error) {
				if len(args) >= 2 && args[0] == "generate" && args[1] == "reality-keypair" {
					return []byte(sampleRealityOutput), nil
				}
				return nil, errors.New("unexpected command")
			},
			RandRead: strings.NewReader("abcd1234"),
		}
	})
	defer reset()

	adapter := &trojan.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		ProtocolOptions: trojan.CreateOptions{
			ServerName: "example.com",
			Reality:    true,
		},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-trojan", protocol.BuildModeProvision)
	if err != nil {
		t.Fatal(err)
	}
	data, err := trojan.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if data.RealityPrivateKey == "" || len(data.RealityShortIDs) == 0 {
		t.Fatalf("expected generated reality material: %#v", data)
	}
}

func TestBuildProtocolData_previewACMEWithECH(t *testing.T) {
	adapter := &trojan.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		ProtocolOptions: trojan.CreateOptions{
			ServerName:  "example.com",
			ACMEDomains: []string{"example.com"},
			ACMEEmail:   "a@b.c",
			ECH:         true,
		},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-trojan", protocol.BuildModePreview)
	if err != nil {
		t.Fatal(err)
	}
	data, err := trojan.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !data.ECHEnabled || data.ECHKeyPath != "/preview/obscura-ech.key" {
		t.Fatalf("unexpected preview ech: %#v", data)
	}
}

func TestBuildProtocolData_previewCertPathsWithECH(t *testing.T) {
	adapter := &trojan.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		ProtocolOptions: trojan.CreateOptions{
			ServerName: "example.com",
			CertPath:   "/tmp/c.crt",
			KeyPath:    "/tmp/c.key",
			ECH:        true,
		},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-trojan", protocol.BuildModePreview)
	if err != nil {
		t.Fatal(err)
	}
	data, err := trojan.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if data.CertPath != "/tmp/c.crt" || !data.ECHEnabled || data.ECHKeyPath != "/preview/obscura-ech.key" {
		t.Fatalf("unexpected preview cert+ech: %#v", data)
	}
}

func TestBuildProtocolData_previewECHWithoutCert(t *testing.T) {
	adapter := &trojan.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	spec := domain.CreateVPNSpec{
		ProtocolOptions: trojan.CreateOptions{
			ServerName: "example.com",
			ECH:        true,
		},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-trojan", protocol.BuildModePreview)
	if err != nil {
		t.Fatal(err)
	}
	data, err := trojan.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !data.ECHEnabled || data.ECHKeyPath != "/preview/obscura-ech.key" {
		t.Fatalf("unexpected preview ech placeholders: %#v", data)
	}
}

func TestBuildProtocolData_provisionACMEWithECH(t *testing.T) {
	reset := trojan.SetTLSGenProviderForTest(func() *trojan.TLSGen {
		return &trojan.TLSGen{
			RunCommand: func(_ string, args ...string) ([]byte, error) {
				if len(args) >= 2 && args[0] == "generate" && args[1] == "ech-keypair" {
					return []byte(sampleECHOutput), nil
				}
				return nil, errors.New("unexpected")
			},
		}
	})
	defer reset()

	adapter := &trojan.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	ensureCertsDir(t, ctx)
	spec := domain.CreateVPNSpec{
		ProtocolOptions: trojan.CreateOptions{
			ACMEDomains: []string{"example.com"},
			ACMEEmail:   "a@b.c",
			ECH:         true,
		},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-trojan", protocol.BuildModeProvision)
	if err != nil {
		t.Fatal(err)
	}
	data, err := trojan.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !data.ECHEnabled || data.ECHKeyPath == "" {
		t.Fatalf("expected provision ech: %#v", data)
	}
}

func TestBuildProtocolData_provisionCertPathsWithECH(t *testing.T) {
	reset := trojan.SetTLSGenProviderForTest(func() *trojan.TLSGen {
		return &trojan.TLSGen{
			RunCommand: func(_ string, args ...string) ([]byte, error) {
				return []byte(sampleECHOutput), nil
			},
		}
	})
	defer reset()

	adapter := &trojan.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	ensureCertsDir(t, ctx)
	spec := domain.CreateVPNSpec{
		ProtocolOptions: trojan.CreateOptions{
			ServerName: "example.com",
			CertPath:   "/tmp/trojan.crt",
			KeyPath:    "/tmp/trojan.key",
			ECH:        true,
		},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-trojan", protocol.BuildModeProvision)
	if err != nil {
		t.Fatal(err)
	}
	data, err := trojan.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if data.ECHKeyPath == "" {
		t.Fatalf("expected ech key path: %#v", data)
	}
}

func TestBuildProtocolData_provisionSelfSignedWithECH(t *testing.T) {
	reset := trojan.SetTLSGenProviderForTest(func() *trojan.TLSGen {
		return &trojan.TLSGen{
			RunCommand: func(_ string, _ ...string) ([]byte, error) {
				return []byte(sampleECHOutput), nil
			},
		}
	})
	defer reset()

	adapter := &trojan.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	ensureCertsDir(t, ctx)
	spec := domain.CreateVPNSpec{
		ProtocolOptions: trojan.CreateOptions{
			ServerName: "example.com",
			ECH:        true,
		},
	}
	raw, err := adapter.BuildProtocolData(ctx, spec, "vpn-trojan", protocol.BuildModeProvision)
	if err != nil {
		t.Fatal(err)
	}
	data, err := trojan.ParseProtocolData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if data.ECHKeyPath == "" {
		t.Fatalf("expected ech after self-signed: %#v", data)
	}
}

func TestBuildProtocolData_createOptionsFromSpec(t *testing.T) {
	adapter := &trojan.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	opts := trojan.CreateOptions{ServerName: "example.com"}
	for _, spec := range []domain.CreateVPNSpec{
		{ProtocolOptions: nil},
		{ProtocolOptions: opts},
		{ProtocolOptions: &opts},
		{ProtocolOptions: (*trojan.CreateOptions)(nil)},
	} {
		if _, err := adapter.BuildProtocolData(ctx, spec, "vpn-trojan", protocol.BuildModePreview); err != nil {
			t.Fatalf("spec %#v: %v", spec.ProtocolOptions, err)
		}
	}
}

func TestBuildProtocolData_errors(t *testing.T) {
	adapter := &trojan.Adapter{}
	ctx := testutil.NewBuildContext(t.TempDir())
	_, err := adapter.BuildProtocolData(ctx, domain.CreateVPNSpec{ProtocolOptions: "bad"}, "tag", protocol.BuildModePreview)
	if err == nil || !strings.Contains(err.Error(), "unexpected type") {
		t.Fatalf("expected type error, got %v", err)
	}
	_, err = adapter.BuildProtocolData(ctx, domain.CreateVPNSpec{
		ProtocolOptions: trojan.CreateOptions{Transport: "bad-transport"},
	}, "tag", protocol.BuildModePreview)
	if err == nil || !strings.Contains(err.Error(), "unsupported trojan transport") {
		t.Fatalf("expected transport error, got %v", err)
	}
	_, err = adapter.BuildProtocolData(ctx, domain.CreateVPNSpec{
		ProtocolOptions: trojan.CreateOptions{
			ServerName:          "example.com",
			FallbackForALPNJSON: `{`,
		},
	}, "tag", protocol.BuildModePreview)
	if err == nil || !strings.Contains(err.Error(), "parse fallback_for_alpn json") {
		t.Fatalf("expected fallback json error, got %v", err)
	}
	_, err = adapter.BuildProtocolData(ctx, domain.CreateVPNSpec{
		ProtocolOptions: trojan.CreateOptions{
			ServerName:           "example.com",
			Transport:            "ws",
			TransportHeadersJSON: `{`,
		},
	}, "tag", protocol.BuildModePreview)
	if err == nil || !strings.Contains(err.Error(), "parse transport headers json") {
		t.Fatalf("expected headers json error, got %v", err)
	}
	_, err = adapter.BuildProtocolData(ctx, domain.CreateVPNSpec{
		ProtocolOptions: trojan.CreateOptions{
			RealityUTLSFingerprint: "chrome",
		},
	}, "tag", protocol.BuildModePreview)
	if err == nil || !strings.Contains(err.Error(), "reality fingerprint requires reality") {
		t.Fatalf("expected fingerprint error, got %v", err)
	}
	_, err = adapter.BuildProtocolData(ctx, domain.CreateVPNSpec{
		ProtocolOptions: trojan.CreateOptions{
			Reality:                true,
			RealityUTLSFingerprint: "bad-fp",
		},
	}, "tag", protocol.BuildModePreview)
	if err == nil || !strings.Contains(err.Error(), "unsupported reality fingerprint") {
		t.Fatalf("expected invalid fingerprint error, got %v", err)
	}
	_, err = adapter.BuildProtocolData(ctx, domain.CreateVPNSpec{
		ProtocolOptions: trojan.CreateOptions{ACMEDomains: []string{"example.com"}},
	}, "tag", protocol.BuildModePreview)
	if err == nil || !strings.Contains(err.Error(), "acme email is required") {
		t.Fatalf("expected acme email validation error, got %v", err)
	}
	_, err = adapter.BuildProtocolData(ctx, domain.CreateVPNSpec{
		ProtocolOptions: trojan.CreateOptions{ServerName: "example.com"},
	}, "tag", protocol.BuildMode(99))
	if err == nil || !strings.Contains(err.Error(), "unknown build mode") {
		t.Fatalf("expected unknown mode error, got %v", err)
	}
}

func TestBuildProtocolData_provisionErrors(t *testing.T) {
	t.Run("reality keypair", func(t *testing.T) {
		reset := trojan.SetTLSGenProviderForTest(func() *trojan.TLSGen {
			return &trojan.TLSGen{
				RunCommand: func(string, ...string) ([]byte, error) {
					return []byte("fail"), errors.New("exec failed")
				},
			}
		})
		defer reset()
		adapter := &trojan.Adapter{}
		ctx := testutil.NewBuildContext(t.TempDir())
		_, err := adapter.BuildProtocolData(ctx, domain.CreateVPNSpec{
			ProtocolOptions: trojan.CreateOptions{Reality: true, ServerName: "example.com"},
		}, "tag", protocol.BuildModeProvision)
		if err == nil || !strings.Contains(err.Error(), "generate reality keypair") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("reality short id", func(t *testing.T) {
		reset := trojan.SetTLSGenProviderForTest(func() *trojan.TLSGen {
			return &trojan.TLSGen{
				RunCommand: func(string, ...string) ([]byte, error) {
					return []byte(sampleRealityOutput), nil
				},
				RandRead: errReader{},
			}
		})
		defer reset()
		adapter := &trojan.Adapter{}
		ctx := testutil.NewBuildContext(t.TempDir())
		_, err := adapter.BuildProtocolData(ctx, domain.CreateVPNSpec{
			ProtocolOptions: trojan.CreateOptions{
				Reality: true, ServerName: "example.com", RealityPrivateKey: "existing-key",
			},
		}, "tag", protocol.BuildModeProvision)
		if err == nil || !strings.Contains(err.Error(), "generate reality short_id") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("manifest save cert paths", func(t *testing.T) {
		adapter := &trojan.Adapter{}
		failCtx := &manifestFailCtx{BuildContext: testutil.NewBuildContext(t.TempDir())}
		_, err := adapter.BuildProtocolData(failCtx, domain.CreateVPNSpec{
			ProtocolOptions: trojan.CreateOptions{
				ServerName: "example.com", CertPath: "/tmp/a.crt", KeyPath: "/tmp/a.key",
			},
		}, "tag", protocol.BuildModeProvision)
		if err == nil || !strings.Contains(err.Error(), "manifest save failed") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("manifest save self-signed", func(t *testing.T) {
		adapter := &trojan.Adapter{}
		failCtx := &manifestFailCtx{BuildContext: testutil.NewBuildContext(t.TempDir())}
		_, err := adapter.BuildProtocolData(failCtx, domain.CreateVPNSpec{
			ProtocolOptions: trojan.CreateOptions{ServerName: "example.com"},
		}, "tag", protocol.BuildModeProvision)
		if err == nil || !strings.Contains(err.Error(), "manifest save failed") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("cert generation", func(t *testing.T) {
		adapter := &trojan.Adapter{}
		f := filepath.Join(t.TempDir(), "not-a-dir")
		if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		ctx := testutil.NewBuildContext(f)
		_, err := adapter.BuildProtocolData(ctx, domain.CreateVPNSpec{
			ProtocolOptions: trojan.CreateOptions{ServerName: "example.com"},
		}, "tag", protocol.BuildModeProvision)
		if err == nil || !strings.Contains(err.Error(), "generate tls certificate") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("ech generation", func(t *testing.T) {
		reset := trojan.SetTLSGenProviderForTest(func() *trojan.TLSGen {
			return &trojan.TLSGen{
				RunCommand: func(string, ...string) ([]byte, error) {
					return nil, errors.New("ech failed")
				},
			}
		})
		defer reset()
		adapter := &trojan.Adapter{}
		ctx := testutil.NewBuildContext(t.TempDir())
		_, err := adapter.BuildProtocolData(ctx, domain.CreateVPNSpec{
			ProtocolOptions: trojan.CreateOptions{
				ServerName: "example.com", CertPath: "/tmp/a.crt", KeyPath: "/tmp/a.key", ECH: true,
			},
		}, "tag", protocol.BuildModeProvision)
		if err == nil || !strings.Contains(err.Error(), "generate ech keypair") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("ech manifest save", func(t *testing.T) {
		reset := trojan.SetTLSGenProviderForTest(func() *trojan.TLSGen {
			return &trojan.TLSGen{
				RunCommand: func(string, ...string) ([]byte, error) {
					return []byte(sampleECHOutput), nil
				},
			}
		})
		defer reset()
		adapter := &trojan.Adapter{}
		failCtx := &manifestFailCtx{BuildContext: testutil.NewBuildContext(t.TempDir())}
		ensureCertsDir(t, failCtx.BuildContext)
		_, err := adapter.BuildProtocolData(failCtx, domain.CreateVPNSpec{
			ProtocolOptions: trojan.CreateOptions{
				ServerName: "example.com", ECH: true,
			},
		}, "tag", protocol.BuildModeProvision)
		if err == nil || !strings.Contains(err.Error(), "manifest save failed") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestBuildCreateProtocolData_transports(t *testing.T) {
	headers, _ := json.Marshal(map[string]string{"X-Test": "1"})
	for _, transport := range []struct {
		name string
		opts trojan.CreateOptions
		want string
	}{
		{"tcp", trojan.CreateOptions{Transport: "tcp"}, ""},
		{"quic", trojan.CreateOptions{Transport: "quic"}, "quic"},
		{"http host", trojan.CreateOptions{Transport: "http", TransportHost: "h.example.com", TransportPath: "/p"}, "http"},
		{"http hosts", trojan.CreateOptions{Transport: "http", TransportHosts: []string{"a", "b"}, TransportPath: "/p"}, "http"},
		{"ws", trojan.CreateOptions{Transport: "ws", TransportPath: "/w", WSMaxEarlyData: 100, WSEarlyDataHeaderName: "Sec-WebSocket-Protocol"}, "ws"},
		{"grpc", trojan.CreateOptions{Transport: "grpc", TransportServiceName: "svc", GRPCPermitWithoutStream: true}, "grpc"},
		{"httpupgrade", trojan.CreateOptions{Transport: "httpupgrade", TransportHost: "h", TransportPath: "/u"}, "httpupgrade"},
	} {
		t.Run(transport.name, func(t *testing.T) {
			o := transport.opts
			o.ServerName = "example.com"
			if transport.name == "http host" || transport.name == "ws" || transport.name == "httpupgrade" {
				o.TransportHeadersJSON = string(headers)
			}
			data, err := trojan.BuildCreateProtocolDataForTest("fallback.host", o)
			if err != nil {
				t.Fatal(err)
			}
			if transport.name == "tcp" && data.TransportType != "" {
				t.Fatalf("tcp transport type = %q", data.TransportType)
			}
			if transport.want != "" && data.TransportType != transport.want {
				t.Fatalf("transport type = %q want %q", data.TransportType, transport.want)
			}
		})
	}
	data, err := trojan.BuildCreateProtocolDataForTest("fallback.host", trojan.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if data.ServerName != "fallback.host" {
		t.Fatalf("default server name = %q", data.ServerName)
	}
	if len(data.ALPN) != 2 || data.ALPN[0] != "h2" {
		t.Fatalf("default alpn = %#v", data.ALPN)
	}
}

func TestBuildCreateProtocolData_httpupgradeALPN(t *testing.T) {
	data, err := trojan.BuildCreateProtocolDataForTest("host.example.com", trojan.CreateOptions{
		Transport: "httpupgrade", TransportPath: "/up",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(data.ALPN) != 1 || data.ALPN[0] != "http/1.1" {
		t.Fatalf("httpupgrade alpn = %#v, want [http/1.1]", data.ALPN)
	}
}

func TestBuildCreateProtocolData_acmeAndFallback(t *testing.T) {
	data, err := trojan.BuildCreateProtocolDataForTest("host", trojan.CreateOptions{
		ACMEDomains:              []string{"example.com"},
		ACMEEmail:                "a@b.c",
		ACMEProvider:             "letsencrypt",
		ACMEDataDirectory:        "/data",
		ACMEDefaultServerName:    "example.com",
		ACMEDisableHTTPChallenge: true,
		FallbackForALPNJSON:      `{"h2":{"server":"127.0.0.1","server_port":8080}}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if data.ACME == nil || len(data.FallbackForALPN) == 0 {
		t.Fatalf("unexpected acme/fallback: %#v", data)
	}
}

func TestResolveRealityUTLSFingerprint(t *testing.T) {
	fp, err := trojan.ResolveRealityUTLSFingerprintForTest(true, "")
	if err != nil || fp == "" {
		t.Fatalf("default reality fp: %q, %v", fp, err)
	}
	fp, err = trojan.ResolveRealityUTLSFingerprintForTest(true, "chrome")
	if err != nil || fp != "chrome" {
		t.Fatalf("explicit fp: %q, %v", fp, err)
	}
	_, err = trojan.ResolveRealityUTLSFingerprintForTest(false, "chrome")
	if err == nil {
		t.Fatal("expected error without reality")
	}
	fp, err = trojan.ResolveRealityUTLSFingerprintForTest(false, "")
	if err != nil || fp != "" {
		t.Fatalf("no reality no fp: %q, %v", fp, err)
	}
}

func TestECHServerName(t *testing.T) {
	if got := trojan.ECHServerNameForTest("sn", nil); got != "sn" {
		t.Fatalf("got %q", got)
	}
	if got := trojan.ECHServerNameForTest("", []string{"acme.example.com"}); got != "acme.example.com" {
		t.Fatalf("got %q", got)
	}
	if got := trojan.ECHServerNameForTest("", nil); got != "localhost" {
		t.Fatalf("got %q", got)
	}
}

func TestApplyPreviewTLS_realityHandshakeDefault(t *testing.T) {
	data := trojan.ProtocolData{ServerName: "example.com", RealityEnabled: true}
	trojan.ApplyPreviewTLSForTest(&data, trojan.CreateOptions{Reality: true})
	if data.RealityHandshakeServer != "example.com" {
		t.Fatalf("handshake server = %q", data.RealityHandshakeServer)
	}
}

func TestSetupTLS_existingECHKeyPath(t *testing.T) {
	data := trojan.ProtocolData{
		CertPath: "/a.crt", KeyPath: "/a.key", ECHEnabled: true, ECHKeyPath: "/existing-ech.key",
	}
	ctx := testutil.NewBuildContext(t.TempDir())
	if err := trojan.SetupTLSForTest(ctx, &data, "tag", trojan.CreateOptions{
		CertPath: "/a.crt", KeyPath: "/a.key", ECH: true,
	}); err != nil {
		t.Fatal(err)
	}
	if data.ECHKeyPath != "/existing-ech.key" {
		t.Fatalf("ech key path changed: %q", data.ECHKeyPath)
	}
}

func TestSetupTLS_realityExistingKeys(t *testing.T) {
	data := trojan.ProtocolData{
		ServerName: "example.com", RealityEnabled: true,
		RealityPrivateKey: "key", RealityShortIDs: []string{"abcd"},
	}
	ctx := testutil.NewBuildContext(t.TempDir())
	if err := trojan.SetupTLSForTest(ctx, &data, "tag", trojan.CreateOptions{Reality: true}); err != nil {
		t.Fatal(err)
	}
}

func TestSetupTLS_acmeNoECH(t *testing.T) {
	data := trojan.ProtocolData{
		ACME: &trojan.ACMEOptions{Domains: []string{"example.com"}, Email: "a@b.c"},
	}
	ctx := testutil.NewBuildContext(t.TempDir())
	if err := trojan.SetupTLSForTest(ctx, &data, "tag", trojan.CreateOptions{
		ACMEDomains: []string{"example.com"},
	}); err != nil {
		t.Fatal(err)
	}
}
