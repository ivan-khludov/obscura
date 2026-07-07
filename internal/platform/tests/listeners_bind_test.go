package platform_test

import (
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/ivan-khludov/obscura/internal/platform"
)

type mockCloser struct{}

func (mockCloser) Close() error { return nil }

func openFileErr() func(string) (io.ReadCloser, error) {
	return func(string) (io.ReadCloser, error) { return nil, errors.New("no proc") }
}

func TestPortChecker_portBoundBindTest_TCP(t *testing.T) {
	t.Run("free port", func(t *testing.T) {
		checker := platform.PortChecker{
			OpenFile: openFileErr(),
			ListenTCP: func(_, _ string) (interface{ Close() error }, error) {
				return mockCloser{}, nil
			},
		}
		bound, err := checker.LocalPortBound("tcp", 65000)
		if err != nil {
			t.Fatal(err)
		}
		if bound {
			t.Fatal("expected free port")
		}
	})

	t.Run("already in use", func(t *testing.T) {
		checker := platform.PortChecker{
			OpenFile: openFileErr(),
			ListenTCP: func(_, _ string) (interface{ Close() error }, error) {
				return nil, fmt.Errorf("listen tcp 127.0.0.1:65000: bind: address already in use")
			},
		}
		bound, err := checker.LocalPortBound("tcp", 65000)
		if err != nil {
			t.Fatal(err)
		}
		if !bound {
			t.Fatal("expected bound port")
		}
	})

	t.Run("other error", func(t *testing.T) {
		checker := platform.PortChecker{
			OpenFile: openFileErr(),
			ListenTCP: func(_, _ string) (interface{ Close() error }, error) {
				return nil, errors.New("permission denied")
			},
		}
		_, err := checker.LocalPortBound("tcp", 65000)
		if err == nil {
			t.Fatal("expected listen error")
		}
	})
}

func TestPortChecker_portBoundBindTest_UDP(t *testing.T) {
	t.Run("free port", func(t *testing.T) {
		checker := platform.PortChecker{
			OpenFile: openFileErr(),
			ListenPacket: func(_, _ string) (interface{ Close() error }, error) {
				return mockCloser{}, nil
			},
		}
		bound, err := checker.LocalPortBound("udp", 65001)
		if err != nil {
			t.Fatal(err)
		}
		if bound {
			t.Fatal("expected free port")
		}
	})

	t.Run("already in use", func(t *testing.T) {
		checker := platform.PortChecker{
			OpenFile: openFileErr(),
			ListenPacket: func(_, _ string) (interface{ Close() error }, error) {
				return nil, fmt.Errorf("listen udp 127.0.0.1:65001: bind: address already in use")
			},
		}
		bound, err := checker.LocalPortBound("udp", 65001)
		if err != nil {
			t.Fatal(err)
		}
		if !bound {
			t.Fatal("expected bound port")
		}
	})

	t.Run("other error", func(t *testing.T) {
		checker := platform.PortChecker{
			OpenFile: openFileErr(),
			ListenPacket: func(_, _ string) (interface{ Close() error }, error) {
				return nil, errors.New("permission denied")
			},
		}
		_, err := checker.LocalPortBound("udp", 65001)
		if err == nil {
			t.Fatal("expected listen error")
		}
	})
}

func TestPortChecker_BindTest_UnsupportedNetwork(t *testing.T) {
	var checker platform.PortChecker
	_, err := checker.BindTest("icmp", 80)
	if err == nil {
		t.Fatal("expected unsupported network error")
	}
}

func TestPortChecker_listenHooks_Default(t *testing.T) {
	checker := platform.PortChecker{OpenFile: openFileErr()}
	bound, err := checker.LocalPortBound("tcp", 65002)
	if err != nil {
		t.Fatalf("tcp bind probe: %v", err)
	}
	if bound {
		t.Fatal("expected free tcp port")
	}

	bound, err = checker.LocalPortBound("udp", 65003)
	if err != nil {
		t.Skipf("udp bind probe unavailable: %v", err)
	}
	if bound {
		t.Fatal("expected free udp port")
	}
}
