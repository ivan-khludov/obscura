package service_test

import (
	"context"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/service"
)

func TestRemoveVmessCerts(t *testing.T) {
	svc, _ := newTestService(t)
	result, err := svc.CreateVPN(context.Background(), service.CreateVPNInput{
		Name: "vm", Protocol: "vmess", Enabled: false,
		Listen: domain.ListenOptions{ListenPort: 1444},
		VMess:  service.VMessCreateOptions{ServerName: "example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	svc.RemoveVmessCertsForTest(result.VPN)
	svc.RemoveVmessCertsForTest(&domain.VPN{Protocol: "socks5"})
	svc.RemoveVmessCertsForTest(&domain.VPN{Protocol: "vmess", ProtocolData: []byte("bad")})
}
