package service_test

import (
	"context"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/service"
)

func TestRemoveVlessCerts(t *testing.T) {
	svc, _ := newTestService(t)
	result, err := svc.CreateVPN(context.Background(), service.CreateVPNInput{
		Name: "vl", Protocol: "vless", Enabled: false,
		Listen: domain.ListenOptions{ListenPort: 1445},
		VLESS:  service.VLESSCreateOptions{ServerName: "example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	svc.RemoveVlessCertsForTest(result.VPN)
	svc.RemoveVlessCertsForTest(&domain.VPN{Protocol: "vless", ProtocolData: []byte("bad")})
}
