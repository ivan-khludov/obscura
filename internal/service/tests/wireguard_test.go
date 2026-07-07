package service_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/wireguard"
	"github.com/ivan-khludov/obscura/internal/runtime"
	"github.com/ivan-khludov/obscura/internal/service"
)

func TestFirewallRuleSpecs(t *testing.T) {
	specs := service.FirewallRuleSpecsForTest(443, []string{"tcp", "udp", ""})
	if len(specs) != 2 {
		t.Fatalf("specs=%#v", specs)
	}
}

func TestGenerateWireguardClientCredentials(t *testing.T) {
	svc, _ := newTestService(t)
	pub, priv, err := svc.GenerateWireguardClientCredentialsForTest()
	if err != nil || pub == "" || priv == "" {
		t.Fatalf("keys: pub=%q priv=%q err=%v", pub, priv, err)
	}
}

func TestGenerateWireguardClientCredentialsError(t *testing.T) {
	svc, _ := newTestService(t)
	svc.SetWireguardKeyGenForTest(service.WireguardKeyGen{GenerateKeypair: func() (wireguard.Keypair, error) {
		return wireguard.Keypair{}, fmt.Errorf("failed")
	}})
	if _, _, err := svc.GenerateWireguardClientCredentialsForTest(); err == nil {
		t.Fatal("expected error")
	}
}

func TestOpenCloseFirewallPort(t *testing.T) {
	dir := t.TempDir()
	fw := &trackingFirewall{}
	svc, _ := newTestService(t)
	_ = dir
	ctx := context.Background()
	svc.OpenFirewallPortForTest(ctx, 9999, []string{"tcp"})
	svc.CloseFirewallPortForTest(ctx, 9999, []string{"tcp"})
	_ = fw
}

func TestNeedsInitialClientValidatePath(t *testing.T) {
	reg := runtime.NewProtocolRegistry()
	adapter, _ := reg.Get("socks5")
	if !service.NeedsInitialClientForTest(adapter, service.ToVPNConfigForTest(&domain.VPN{Protocol: "socks5"})) {
		t.Fatal("expected needs client via DataBuilder")
	}
}
