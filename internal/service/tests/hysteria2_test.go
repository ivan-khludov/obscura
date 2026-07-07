package service_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/hysteria2"
	"github.com/ivan-khludov/obscura/internal/service"
)

func TestRemoveHysteria2Certs(t *testing.T) {
	svc, _ := newTestService(t)
	result, err := svc.CreateVPN(context.Background(), service.CreateVPNInput{
		Name: "hy", Protocol: "hysteria2", Enabled: false,
		Listen:    domain.ListenOptions{ListenPort: 1446},
		Hysteria2: service.Hysteria2CreateOptions{ServerName: "example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	svc.RemoveHysteria2CertsForTest(result.VPN)
	svc.RemoveHysteria2CertsForTest(&domain.VPN{Protocol: "hysteria2", ProtocolData: []byte("bad")})
}

func TestRemoveHysteria2CertsWithECHFile(t *testing.T) {
	svc, _ := newTestService(t)
	echPath := filepath.Join(svc.DataDir(), "ech.key")
	if err := os.WriteFile(echPath, []byte("ech"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := hysteria2.MarshalProtocolData(hysteria2.ProtocolData{
		CertPath:   filepath.Join(svc.DataDir(), "c.crt"),
		KeyPath:    filepath.Join(svc.DataDir(), "c.key"),
		ECHKeyPath: echPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	svc.RemoveHysteria2CertsForTest(&domain.VPN{Protocol: "hysteria2", ProtocolData: raw})
}
