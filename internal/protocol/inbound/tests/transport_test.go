package inbound_test

import (
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol/inbound"
)

func TestRenderTransport(t *testing.T) {
	if got := inbound.RenderTransport("", nil, nil, nil, nil); got != nil {
		t.Fatalf("got %#v", got)
	}
	if got := inbound.RenderTransport("quic", nil, nil, nil, nil); got["type"] != "quic" {
		t.Fatalf("got %#v", got)
	}
	if got := inbound.RenderTransport("unknown", nil, nil, nil, nil); got != nil {
		t.Fatalf("got %#v", got)
	}
}

func TestALPNForTransport(t *testing.T) {
	if got := inbound.ALPNForTransport("httpupgrade", []string{"h2", "http/1.1"}); len(got) != 1 || got[0] != "http/1.1" {
		t.Fatalf("httpupgrade alpn = %#v, want [http/1.1]", got)
	}
	def := []string{"h2", "http/1.1"}
	if got := inbound.ALPNForTransport("ws", def); len(got) != 2 || got[0] != "h2" {
		t.Fatalf("ws alpn = %#v, want %#v", got, def)
	}
}

func TestRenderTransportHTTP(t *testing.T) {
	got := inbound.RenderTransportHTTP(&inbound.TransportHTTP{
		Host: []string{"h"}, Path: "/p", Method: "GET", Headers: map[string]string{"X": "1"},
		IdleTimeout: "30s", PingTimeout: "5s",
	})
	if got["type"] != "http" || got["path"] != "/p" {
		t.Fatalf("got %#v", got)
	}
}

func TestRenderTransportWS(t *testing.T) {
	got := inbound.RenderTransportWS(&inbound.TransportWS{
		Path: "/ws", Headers: map[string]string{"H": "v"}, MaxEarlyData: 1024, EarlyDataHeaderName: "Ed",
	})
	if got["type"] != "ws" || got["max_early_data"] != 1024 {
		t.Fatalf("got %#v", got)
	}
}

func TestRenderTransportGRPC(t *testing.T) {
	got := inbound.RenderTransportGRPC(&inbound.TransportGRPC{
		ServiceName: "svc", IdleTimeout: "30s", PingTimeout: "5s", PermitWithoutStream: true,
	})
	if got["type"] != "grpc" || got["permit_without_stream"] != true {
		t.Fatalf("got %#v", got)
	}
}

func TestRenderTransportHTTPUpgrade(t *testing.T) {
	got := inbound.RenderTransportHTTPUpgrade(&inbound.TransportHTTPUpgrade{
		Host: "h", Path: "/u", Headers: map[string]string{"A": "b"},
	})
	if got["type"] != "httpupgrade" || got["host"] != "h" {
		t.Fatalf("got %#v", got)
	}
}

func TestRenderTransport_dispatch(t *testing.T) {
	http := &inbound.TransportHTTP{Path: "/"}
	ws := &inbound.TransportWS{Path: "/"}
	grpc := &inbound.TransportGRPC{ServiceName: "s"}
	hu := &inbound.TransportHTTPUpgrade{Path: "/"}
	if inbound.RenderTransport("http", http, nil, nil, nil)["type"] != "http" {
		t.Fatal("http dispatch failed")
	}
	if inbound.RenderTransport("ws", nil, ws, nil, nil)["type"] != "ws" {
		t.Fatal("ws dispatch failed")
	}
	if inbound.RenderTransport("grpc", nil, nil, grpc, nil)["type"] != "grpc" {
		t.Fatal("grpc dispatch failed")
	}
	if inbound.RenderTransport("httpupgrade", nil, nil, nil, hu)["type"] != "httpupgrade" {
		t.Fatal("httpupgrade dispatch failed")
	}
}

func TestRenderTransport_minimalFields(t *testing.T) {
	if inbound.RenderTransportHTTP(&inbound.TransportHTTP{})["type"] != "http" {
		t.Fatal("expected http type")
	}
	if inbound.RenderTransportWS(&inbound.TransportWS{})["type"] != "ws" {
		t.Fatal("expected ws type")
	}
	if inbound.RenderTransportGRPC(&inbound.TransportGRPC{})["type"] != "grpc" {
		t.Fatal("expected grpc type")
	}
	if inbound.RenderTransportHTTPUpgrade(&inbound.TransportHTTPUpgrade{})["type"] != "httpupgrade" {
		t.Fatal("expected httpupgrade type")
	}
}
