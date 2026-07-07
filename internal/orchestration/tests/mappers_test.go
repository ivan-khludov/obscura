package orchestration_test

import (
	"testing"
	"time"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/service"
)

func TestMapCreateVPNResult(t *testing.T) {
	if orchestration.MapCreateVPNResult(nil) != nil {
		t.Fatal("expected nil for nil input")
	}

	now := time.Now()
	vpn := &domain.VPN{
		ID: 1, Name: "main", Protocol: "socks5", Tag: "in-main",
		Enabled: true, CreatedAt: now, UpdatedAt: now,
	}
	client := &domain.Client{
		ID: 2, VPNID: 1, Name: "phone", Username: "u", Password: "p",
		Enabled: true, CreatedAt: now, UpdatedAt: now,
	}

	t.Run("full result", func(t *testing.T) {
		out := orchestration.MapCreateVPNResult(&service.CreateVPNResult{
			VPN: vpn, Client: client, URI: "uri://test",
		})
		if out == nil || out.VPN == nil || out.Client == nil {
			t.Fatal("expected vpn and client views")
		}
		if out.VPN.Name != "main" || out.Client.Name != "phone" || out.URI != "uri://test" {
			t.Fatalf("unexpected result: %+v", out)
		}
	})

	t.Run("vpn only", func(t *testing.T) {
		out := orchestration.MapCreateVPNResult(&service.CreateVPNResult{VPN: vpn})
		if out.VPN == nil || out.Client != nil {
			t.Fatalf("unexpected partial result: %+v", out)
		}
	})

	t.Run("client only", func(t *testing.T) {
		out := orchestration.MapCreateVPNResult(&service.CreateVPNResult{Client: client, URI: "uri"})
		if out.VPN != nil || out.Client == nil {
			t.Fatalf("unexpected partial result: %+v", out)
		}
	})

	t.Run("empty result", func(t *testing.T) {
		out := orchestration.MapCreateVPNResult(&service.CreateVPNResult{})
		if out.VPN != nil || out.Client != nil {
			t.Fatalf("expected empty views, got %+v", out)
		}
	})
}

func TestMapCreateVPNResult_CopiesProtocolData(t *testing.T) {
	raw := []byte(`{"tls":true}`)
	vpn := &domain.VPN{ID: 1, Name: "web", Protocol: "http", ProtocolData: raw}
	out := orchestration.MapCreateVPNResult(&service.CreateVPNResult{VPN: vpn})
	raw[0] = 'X'
	if out.VPN.ProtocolData[0] == 'X' {
		t.Fatal("expected protocol data copy, not shared slice")
	}
}
