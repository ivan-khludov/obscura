package service_test

import (
	"context"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/service"
)

func TestUseCaseDelegation(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	in := service.CreateVPNInput{
		Name: "sub", Protocol: "socks5", Enabled: false,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 12001},
	}

	created, err := svc.VPNs.Create(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.VPNs.Get(ctx, "sub")
	if err != nil || got.Name != created.VPN.Name {
		t.Fatalf("get vpn: %v %#v", err, got)
	}
	list, err := svc.VPNs.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list vpns: %v len=%d", err, len(list))
	}

	client, uri, err := svc.Clients.Add(ctx, service.AddClientInput{VPNName: "sub", Name: "phone"}, false)
	if err != nil || uri == "" || client.Name != "phone" {
		t.Fatalf("add client: %v uri=%q client=%#v", err, uri, client)
	}
	clients, err := svc.Clients.List(ctx, "sub")
	if err != nil || len(clients) != 2 {
		t.Fatalf("list clients: %v len=%d", err, len(clients))
	}
	gotURI, err := svc.Clients.URI(ctx, "sub", "phone")
	if err != nil || gotURI == "" {
		t.Fatalf("client uri: %v", err)
	}
	qr, err := svc.Clients.QRContent(ctx, "sub", "phone")
	if err != nil || qr == "" {
		t.Fatalf("qr content: %v", err)
	}
	pw, uri, err := svc.Clients.RotatePassword(ctx, "sub", "phone")
	if err != nil || pw == "" || uri == "" {
		t.Fatalf("rotate: %v", err)
	}
	if _, err := svc.Clients.Update(ctx, service.UpdateClientInput{VPNName: "sub", Name: "phone"}, false); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.System.Apply(ctx, true); err != nil {
		t.Fatal(err)
	}
	if err := svc.Bootstrapper.Bootstrap(ctx, service.BootstrapOptions{}); err != nil {
		t.Fatal(err)
	}
	path, err := svc.Maintenance.CreateBackup(ctx)
	if err != nil || path == "" {
		t.Fatalf("backup: %v path=%q", err, path)
	}
	entries, err := svc.Maintenance.ListBackups(ctx)
	if err != nil || len(entries) != 1 {
		t.Fatalf("list backups: %v len=%d", err, len(entries))
	}
	plan := svc.Maintenance.UninstallPlan()
	_ = plan
	if err := svc.VPNs.Delete(ctx, "sub"); err != nil {
		t.Fatal(err)
	}
}
