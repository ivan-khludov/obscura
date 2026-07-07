package orchestration_test

import (
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/orchestration"
)

func TestApplyListenPatch(t *testing.T) {
	current := domain.ListenOptions{
		Listen:     "0.0.0.0",
		ListenPort: 1080,
	}
	listen := "127.0.0.1"
	port := 8080
	bind := "eth0"
	routing := "100"
	reuse := true
	netns := "test"
	tcpFastOpen := true
	tcpMultiPath := true
	disableKeepAlive := true
	keepAlive := "30s"
	keepAliveInterval := "10s"
	udpFragment := false
	udpTimeout := "5m"
	detour := "direct"

	out := orchestration.ApplyListenPatch(current, orchestration.ListenPatch{
		Listen:               &listen,
		ListenPort:           &port,
		BindInterface:        &bind,
		RoutingMark:          &routing,
		ReuseAddr:            &reuse,
		Netns:                &netns,
		TCPFastOpen:          &tcpFastOpen,
		TCPMultiPath:         &tcpMultiPath,
		DisableTCPKeepAlive:  &disableKeepAlive,
		TCPKeepAlive:         &keepAlive,
		TCPKeepAliveInterval: &keepAliveInterval,
		UDPFragment:          &udpFragment,
		UDPTimeout:           &udpTimeout,
		Detour:               &detour,
	})
	if out.Listen != listen || out.ListenPort != port {
		t.Fatalf("listen = %q:%d", out.Listen, out.ListenPort)
	}
	if out.BindInterface != bind || out.RoutingMark != routing {
		t.Fatal("expected bind/routing patch")
	}
	if !out.ReuseAddr || out.Netns != netns {
		t.Fatal("expected reuse/netns patch")
	}
	if !out.TCPFastOpen || !out.TCPMultiPath || !out.DisableTCPKeepAlive {
		t.Fatal("expected tcp flags patch")
	}
	if out.TCPKeepAlive != keepAlive || out.TCPKeepAliveInterval != keepAliveInterval {
		t.Fatal("expected keepalive patch")
	}
	if out.UDPFragment || out.UDPTimeout != udpTimeout || out.Detour != detour {
		t.Fatal("expected udp/detour patch")
	}
}

func TestBuildEditVPNInput_HTTPGuards(t *testing.T) {
	name := "web"
	req := orchestration.UpdateVPNRequest{Name: &name}

	_, err := orchestration.BuildEditVPNInput("socks5", req, true, false)
	if err == nil {
		t.Fatal("expected non-http tls enable guard error")
	}

	_, err = orchestration.BuildEditVPNInput("socks5", req, false, true)
	if err == nil {
		t.Fatal("expected non-http tls disable guard error")
	}

	in, err := orchestration.BuildEditVPNInput("http", req, true, false)
	if err != nil {
		t.Fatalf("unexpected error for http tls edit: %v", err)
	}
	if in.HTTPTLS == nil || !*in.HTTPTLS {
		t.Fatalf("expected httptls=true in update input")
	}

	in, err = orchestration.BuildEditVPNInput("http", req, false, true)
	if err != nil {
		t.Fatalf("unexpected error for http tls disable: %v", err)
	}
	if in.HTTPTLS == nil || *in.HTTPTLS {
		t.Fatalf("expected httptls=false in update input")
	}
}

func TestEditRequestParity_ErrorPathConsistency(t *testing.T) {
	host := "vpn.example.com"
	req := orchestration.UpdateVPNRequest{
		ClientHost:      &host,
		ClearClientHost: true,
	}

	_, errA := orchestration.BuildEditVPNInput("socks5", req, false, false)
	_, errB := orchestration.BuildEditVPNInput("socks5", req, false, false)
	if (errA == nil) != (errB == nil) {
		t.Fatalf("expected parity in error path")
	}
	if errA == nil || errA.Error() != errB.Error() {
		t.Fatalf("expected identical error messages, got %v and %v", errA, errB)
	}
}
