package service_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/httpproxy"
	"github.com/ivan-khludov/obscura/internal/service"
)

func TestHTTPCertLifecycle(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	result, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "web", Protocol: "http", HTTPTLS: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8088},
	})
	if err != nil {
		t.Fatal(err)
	}
	svc.RemoveHTTPCertsForTest(result.VPN)
	svc.RemoveHTTPCertsForTest(&domain.VPN{Protocol: "socks5"})
	if err := svc.EnableHTTPTLSForTest(result.VPN); err != nil {
		t.Fatal(err)
	}
	svc.DisableHTTPTLSForTest(result.VPN)
	if err := svc.EnableHTTPTLSForTest(&domain.VPN{Protocol: "socks5"}); err == nil {
		t.Fatal("expected http-only tls error")
	}
}

func TestEnableHTTPTLSCertGenFail(t *testing.T) {
	svc, _ := newTestService(t)
	dir := svc.DataDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	vpn := &domain.VPN{Name: "web", Protocol: "http", Tag: "vpn-web", Listen: domain.ListenOptions{ListenPort: 8089}}
	if err := svc.EnableHTTPTLSForTest(vpn); err == nil {
		t.Fatal("expected cert generation error")
	}
}

func TestEnableHTTPTLSMarshalFail(t *testing.T) {
	svc, _ := newTestService(t)
	svc.SetHTTPMarshalForTest(func(httpproxy.ProtocolData) ([]byte, error) {
		return nil, fmt.Errorf("marshal failed")
	})
	vpn := &domain.VPN{Name: "web", Protocol: "http", Tag: "vpn-web", Listen: domain.ListenOptions{ListenPort: 8090}}
	if err := svc.EnableHTTPTLSForTest(vpn); err == nil {
		t.Fatal("expected marshal error")
	}
}

func TestRemoveHTTPCertsInvalidData(t *testing.T) {
	svc, _ := newTestService(t)
	svc.RemoveHTTPCertsForTest(&domain.VPN{Protocol: "http", ProtocolData: []byte("bad")})
	data, _ := httpproxy.MarshalProtocolData(httpproxy.ProtocolData{TLS: true, CertPath: "", KeyPath: ""})
	svc.RemoveHTTPCertsForTest(&domain.VPN{Protocol: "http", ProtocolData: data})
}
