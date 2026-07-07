package service_test

import (
	"context"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/service"
)

func TestRemoveTUICCerts(t *testing.T) {
	svc, _ := newTestService(t)
	result, err := svc.CreateVPN(context.Background(), service.CreateVPNInput{
		Name: "tc", Protocol: "tuic", Enabled: false,
		Listen: domain.ListenOptions{ListenPort: 1447},
		TUIC:   service.TUICCreateOptions{ServerName: "example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	svc.RemoveTUICCertsForTest(result.VPN)
	svc.RemoveTUICCertsForTest(&domain.VPN{Protocol: "tuic", ProtocolData: []byte("bad")})
}
