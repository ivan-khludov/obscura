package doctor_test

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/doctor"
	"github.com/ivan-khludov/obscura/internal/sysctl"
)

func singBoxActive() func(context.Context) (bool, error) {
	return func(_ context.Context) (bool, error) { return true, nil }
}

func stableSysctl() func(string) (string, error) {
	return func(key string) (string, error) {
		switch key {
		case sysctl.KeyCongestionControl:
			return sysctl.DefaultCongestionControl, nil
		case "net.ipv4.ip_forward":
			return "1", nil
		default:
			return "", nil
		}
	}
}

func findResult(t *testing.T, results []doctor.CheckResult, name string) doctor.CheckResult {
	t.Helper()
	for _, r := range results {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("check %q missing in %#v", name, results)
	return doctor.CheckResult{}
}

func TestHasFailures(t *testing.T) {
	if !doctor.HasFailures([]doctor.CheckResult{{Status: doctor.StatusFail}}) {
		t.Fatal("expected true for fail status")
	}
	if doctor.HasFailures([]doctor.CheckResult{
		{Status: doctor.StatusOK},
		{Status: doctor.StatusWarn},
	}) {
		t.Fatal("expected false for ok/warn only")
	}
}

func TestRun_withoutSingBoxActive(t *testing.T) {
	c := doctor.Checker{SingBoxActive: nil}
	results := c.Run(context.Background())
	for _, r := range results {
		if r.Name == "sing-box" {
			t.Fatal("unexpected sing-box check when SingBoxActive is nil")
		}
	}
}

func TestCheckSingBox_Active(t *testing.T) {
	c := doctor.Checker{SingBoxActive: singBoxActive()}
	r := findResult(t, c.Run(context.Background()), "sing-box")
	if r.Status != doctor.StatusOK {
		t.Fatalf("expected ok, got %#v", r)
	}
}

func TestCheckSingBox_Inactive(t *testing.T) {
	c := doctor.Checker{
		SingBoxActive: func(_ context.Context) (bool, error) { return false, nil },
	}
	r := findResult(t, c.Run(context.Background()), "sing-box")
	if r.Status != doctor.StatusFail {
		t.Fatalf("expected fail, got %#v", r)
	}
}

func TestCheckSingBox_Activating(t *testing.T) {
	c := doctor.Checker{
		SingBoxActive: func(_ context.Context) (bool, error) {
			return false, errors.New("activating")
		},
	}
	r := findResult(t, c.Run(context.Background()), "sing-box")
	if r.Status != doctor.StatusFail || r.Message != "activating" {
		t.Fatalf("unexpected result: %#v", r)
	}
}

func TestCheckListenCheck_TCPListening(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ln.Close(); err != nil {
			t.Errorf("close listener: %v", err)
		}
	})
	port := ln.Addr().(*net.TCPAddr).Port

	c := doctor.Checker{
		SingBoxActive: singBoxActive(),
		ListenChecks: []doctor.ListenCheck{{
			VPNName: "main", Protocol: "socks5", Port: port, Protos: []string{"tcp"},
		}},
	}
	r := findResult(t, c.Run(context.Background()), "main:"+strconv.Itoa(port))
	if r.Status != doctor.StatusOK {
		t.Fatalf("expected ok, got %#v", r)
	}
	if !strings.Contains(r.Message, "tcp/"+strconv.Itoa(port)+" listening") {
		t.Fatalf("unexpected message: %q", r.Message)
	}
}

func TestCheckListenCheck_TCPNotListening(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	c := doctor.Checker{
		SingBoxActive: singBoxActive(),
		ListenChecks: []doctor.ListenCheck{{
			VPNName: "main", Protocol: "socks5", Port: port, Protos: []string{"tcp"},
		}},
	}
	r := findResult(t, c.Run(context.Background()), "main:"+strconv.Itoa(port))
	if r.Status != doctor.StatusWarn {
		t.Fatalf("expected warn, got %#v", r)
	}
	if !strings.Contains(r.Message, "not listening") {
		t.Fatalf("unexpected message: %q", r.Message)
	}
}

func TestCheckListenCheck_udpListening(t *testing.T) {
	port := 12345
	c := doctor.Checker{
		SingBoxActive: singBoxActive(),
		LocalPortBound: func(network string, p int) (bool, error) {
			return network == "udp" && p == port, nil
		},
		ListenChecks: []doctor.ListenCheck{{
			VPNName: "hy", Protocol: "hysteria2", Port: port, Protos: []string{"udp"},
		}},
	}
	r := findResult(t, c.Run(context.Background()), "hy:"+strconv.Itoa(port))
	if r.Status != doctor.StatusOK {
		t.Fatalf("expected ok, got %#v", r)
	}
}

func TestCheckListenCheck_tcpUDP(t *testing.T) {
	port := 54321
	c := doctor.Checker{
		SingBoxActive: singBoxActive(),
		LocalPortBound: func(network string, p int) (bool, error) {
			if p != port {
				return false, nil
			}
			return network == "tcp" || network == "udp", nil
		},
		ListenChecks: []doctor.ListenCheck{{
			VPNName: "wg", Protocol: "wireguard", Port: port, Protos: []string{"tcp", "udp"},
		}},
	}
	r := findResult(t, c.Run(context.Background()), "wg:"+strconv.Itoa(port))
	if r.Status != doctor.StatusOK {
		t.Fatalf("expected ok, got %#v", r)
	}
	if !strings.Contains(r.Message, "tcp+udp/"+strconv.Itoa(port)+" listening") {
		t.Fatalf("unexpected message: %q", r.Message)
	}
}

func TestCheckListenCheck_secondProtoFails(t *testing.T) {
	port := 60000
	c := doctor.Checker{
		SingBoxActive: singBoxActive(),
		LocalPortBound: func(network string, p int) (bool, error) {
			if p != port {
				return false, nil
			}
			return network == "tcp", nil
		},
		ListenChecks: []doctor.ListenCheck{{
			VPNName: "hy", Protocol: "hysteria2", Port: port, Protos: []string{"tcp", "udp"},
		}},
	}
	r := findResult(t, c.Run(context.Background()), "hy:"+strconv.Itoa(port))
	if r.Status != doctor.StatusWarn {
		t.Fatalf("expected warn, got %#v", r)
	}
	if !strings.Contains(r.Message, "udp/"+strconv.Itoa(port)+" not listening") {
		t.Fatalf("unexpected message: %q", r.Message)
	}
}

func TestCheckBoundPort_error(t *testing.T) {
	port := 1080
	c := doctor.Checker{
		SingBoxActive: singBoxActive(),
		LocalPortBound: func(string, int) (bool, error) {
			return false, errors.New("probe failed")
		},
		ListenChecks: []doctor.ListenCheck{{
			VPNName: "main", Protocol: "socks5", Port: port, Protos: []string{"tcp"},
		}},
	}
	r := findResult(t, c.Run(context.Background()), "main:"+strconv.Itoa(port))
	if r.Status != doctor.StatusWarn || r.Message != "probe failed" {
		t.Fatalf("unexpected result: %#v", r)
	}
}

func TestCheckListenCheck_SkippedWhenSingBoxInactive(t *testing.T) {
	c := doctor.Checker{
		SingBoxActive: func(_ context.Context) (bool, error) { return false, nil },
		ListenChecks: []doctor.ListenCheck{{
			VPNName: "main", Protocol: "socks5", Port: 1080, Protos: []string{"tcp"},
		}},
	}
	r := findResult(t, c.Run(context.Background()), "main:1080")
	if r.Status != doctor.StatusWarn || !strings.Contains(r.Message, "skipped") {
		t.Fatalf("unexpected result: %#v", r)
	}
}

func TestCheckCongestion_Match(t *testing.T) {
	current, err := sysctl.ReadCurrent(sysctl.KeyCongestionControl)
	if err != nil {
		t.Skip("sysctl not available:", err)
	}
	c := doctor.Checker{ExpectedCongestionControl: current}
	r := findResult(t, c.Run(context.Background()), "congestion")
	if r.Status != doctor.StatusOK {
		t.Fatalf("expected ok for matching congestion, got %#v", r)
	}
}

func TestCheckCongestion_Mismatch(t *testing.T) {
	current, err := sysctl.ReadCurrent(sysctl.KeyCongestionControl)
	if err != nil {
		t.Skip("sysctl not available:", err)
	}
	c := doctor.Checker{ExpectedCongestionControl: current + "-other"}
	r := findResult(t, c.Run(context.Background()), "congestion")
	if r.Status != doctor.StatusWarn {
		t.Fatalf("expected warn, got %#v", r)
	}
}

func TestCheckCongestion_error(t *testing.T) {
	c := doctor.Checker{
		ReadSysctl: func(key string) (string, error) {
			if key == sysctl.KeyCongestionControl {
				return "", errors.New("read failed")
			}
			return "1", nil
		},
	}
	r := findResult(t, c.Run(context.Background()), "congestion")
	if r.Status != doctor.StatusFail || r.Message != "read failed" {
		t.Fatalf("unexpected result: %#v", r)
	}
}

func TestCheckCongestion_defaultExpected(t *testing.T) {
	c := doctor.Checker{
		ExpectedCongestionControl: "",
		ReadSysctl:                stableSysctl(),
	}
	r := findResult(t, c.Run(context.Background()), "congestion")
	if r.Status != doctor.StatusOK {
		t.Fatalf("expected ok, got %#v", r)
	}
}

func TestCheckForwarding_ok(t *testing.T) {
	c := doctor.Checker{ReadSysctl: stableSysctl()}
	r := findResult(t, c.Run(context.Background()), "ip_forward")
	if r.Status != doctor.StatusOK {
		t.Fatalf("expected ok, got %#v", r)
	}
}

func TestCheckForwarding_warn(t *testing.T) {
	c := doctor.Checker{
		ReadSysctl: func(key string) (string, error) {
			switch key {
			case sysctl.KeyCongestionControl:
				return sysctl.DefaultCongestionControl, nil
			case "net.ipv4.ip_forward":
				return "0", nil
			default:
				return "", nil
			}
		},
	}
	r := findResult(t, c.Run(context.Background()), "ip_forward")
	if r.Status != doctor.StatusWarn {
		t.Fatalf("expected warn, got %#v", r)
	}
}

func TestCheckForwarding_error(t *testing.T) {
	c := doctor.Checker{
		ReadSysctl: func(key string) (string, error) {
			if key == "net.ipv4.ip_forward" {
				return "", errors.New("forward read failed")
			}
			return sysctl.DefaultCongestionControl, nil
		},
	}
	r := findResult(t, c.Run(context.Background()), "ip_forward")
	if r.Status != doctor.StatusFail || r.Message != "forward read failed" {
		t.Fatalf("unexpected result: %#v", r)
	}
}

func TestRun_withSSHPort(t *testing.T) {
	c := doctor.Checker{
		ReadSysctl: stableSysctl(),
		LocalPortBound: func(network string, port int) (bool, error) {
			return network == "tcp" && port == 22, nil
		},
		SSHPort: 22,
	}
	r := findResult(t, c.Run(context.Background()), "ssh_port")
	if r.Status != doctor.StatusOK || !strings.Contains(r.Message, "tcp/22 listening") {
		t.Fatalf("unexpected result: %#v", r)
	}
}

func TestCheckSSHPort_notListening(t *testing.T) {
	c := doctor.Checker{
		ReadSysctl: stableSysctl(),
		LocalPortBound: func(string, int) (bool, error) {
			return false, nil
		},
		SSHPort: 2222,
	}
	r := findResult(t, c.Run(context.Background()), "ssh_port")
	if r.Status != doctor.StatusWarn || !strings.Contains(r.Message, "tcp/2222 not listening") {
		t.Fatalf("unexpected result: %#v", r)
	}
}

func TestCheckSSHPort_error(t *testing.T) {
	c := doctor.Checker{
		ReadSysctl: stableSysctl(),
		LocalPortBound: func(string, int) (bool, error) {
			return false, errors.New("ssh probe failed")
		},
		SSHPort: 22,
	}
	r := findResult(t, c.Run(context.Background()), "ssh_port")
	if r.Status != doctor.StatusWarn || r.Message != "ssh probe failed" {
		t.Fatalf("unexpected result: %#v", r)
	}
}
