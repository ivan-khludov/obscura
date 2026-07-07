package service_test

import (
	"context"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/service"
)

func TestRemoveTrojanCerts(t *testing.T) {
	svc, _ := newTestService(t)
	result, err := svc.CreateVPN(context.Background(), service.CreateVPNInput{
		Name: "tr", Protocol: "trojan", Enabled: false,
		Listen: domain.ListenOptions{ListenPort: 1443},
		Trojan: service.TrojanCreateOptions{ServerName: "example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	svc.RemoveTrojanCertsForTest(result.VPN)
	svc.RemoveVPNCertsForTest(result.VPN)
	svc.RemoveTrojanCertsForTest(&domain.VPN{Protocol: "trojan", ProtocolData: []byte("bad")})
}
