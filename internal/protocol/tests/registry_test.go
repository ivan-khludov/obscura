package protocol_test

import (
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/protocol/httpproxy"
	"github.com/ivan-khludov/obscura/internal/protocol/hysteria2"
	"github.com/ivan-khludov/obscura/internal/protocol/shadowsocks"
	"github.com/ivan-khludov/obscura/internal/protocol/socks5"
	"github.com/ivan-khludov/obscura/internal/protocol/trojan"
	"github.com/ivan-khludov/obscura/internal/protocol/tuic"
	"github.com/ivan-khludov/obscura/internal/protocol/vless"
	"github.com/ivan-khludov/obscura/internal/protocol/vmess"
	"github.com/ivan-khludov/obscura/internal/protocol/wireguard"
)

func registerAllProtocols(reg *protocol.Registry) {
	reg.Register(&httpproxy.Adapter{})
	reg.Register(&trojan.Adapter{})
	reg.Register(&socks5.Adapter{})
	reg.Register(&shadowsocks.Adapter{})
	reg.Register(&wireguard.Adapter{})
	reg.Register(&vmess.Adapter{})
	reg.Register(&vless.Adapter{})
	reg.Register(&hysteria2.Adapter{})
	reg.Register(&tuic.Adapter{})
}

func TestNewRegistry(t *testing.T) {
	reg := protocol.NewRegistry()
	if reg == nil {
		t.Fatal("expected registry")
	}
	if _, err := reg.Get("missing"); err == nil {
		t.Fatal("expected error for missing protocol")
	}
}

func TestRegistry_RegisterAndGet(t *testing.T) {
	reg := protocol.NewRegistry()
	stub := stubProtocol{typ: "custom"}
	reg.Register(stub)
	got, err := reg.Get("custom")
	if err != nil {
		t.Fatal(err)
	}
	if got.Type() != "custom" {
		t.Fatalf("Type = %q", got.Type())
	}
}

func TestRegistry_Register_duplicatePanics(t *testing.T) {
	reg := protocol.NewRegistry()
	reg.Register(stubProtocol{typ: "dup"})
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	reg.Register(stubProtocol{typ: "dup"})
}

func TestRegistry_Get_unknown(t *testing.T) {
	reg := protocol.NewRegistry()
	_, err := reg.Get("unknown")
	if err == nil || !strings.Contains(err.Error(), `unknown protocol "unknown"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRegistryListDisplayOrder(t *testing.T) {
	reg := protocol.NewRegistry()
	registerAllProtocols(reg)

	got := reg.List()
	want := []string{"http", "socks5", "shadowsocks", "trojan", "wireguard", "vmess", "vless", "hysteria2", "tuic"}
	if len(got) != len(want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
	for i, name := range want {
		if got[i] != name {
			t.Fatalf("index %d: got %q want %q (full: %#v)", i, got[i], name, got)
		}
	}
}

func TestRegistry_List_extraProtocolsSorted(t *testing.T) {
	reg := protocol.NewRegistry()
	reg.Register(stubProtocol{typ: "zebra"})
	reg.Register(stubProtocol{typ: "alpha"})
	got := reg.List()
	if len(got) != 2 || got[0] != "alpha" || got[1] != "zebra" {
		t.Fatalf("got %#v", got)
	}
}

func TestDisplayOrder(t *testing.T) {
	if len(protocol.DisplayOrder) == 0 {
		t.Fatal("expected display order")
	}
}

func TestDefaultFirewallProtos(t *testing.T) {
	if len(protocol.DefaultFirewallProtos) == 0 {
		t.Fatal("expected default firewall protos")
	}
}
