package service_test

import (
	"context"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/service"
)

func TestValidateUniquePortExclude(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: false,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 13010},
	}); err != nil {
		t.Fatal(err)
	}
	disabled := false
	if _, err := svc.UpdateVPN(ctx, "main", service.UpdateVPNInput{Enabled: &disabled}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "other", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 13010},
	}); err != nil {
		t.Fatalf("expected enabled vpn on disabled vpn port: %v", err)
	}
}

func TestValidateVPNListenPortSSH(t *testing.T) {
	svc, _ := newTestService(t)
	if err := svc.ValidateVPNListenPort(context.Background(), 22); err == nil {
		t.Fatal("expected ssh port conflict")
	}
}

func TestValidateUniquePortClosedStore(t *testing.T) {
	svc := closedStoreService(t)
	if err := svc.ValidateVPNListenPort(context.Background(), 13011); err == nil {
		t.Fatal("expected store error")
	}
}
