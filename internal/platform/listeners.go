package platform

import (
	"fmt"
	"io"
	"os"
)

// PortChecker inspects local port binding state with injectable OS hooks (for tests).
type PortChecker struct {
	OpenFile     func(name string) (io.ReadCloser, error)
	ListenTCP    func(network, address string) (interface{ Close() error }, error)
	ListenPacket func(network, address string) (interface{ Close() error }, error)
}

func (c PortChecker) openFile(name string) (io.ReadCloser, error) {
	if c.OpenFile != nil {
		return c.OpenFile(name)
	}
	return os.Open(name)
}

// LocalPortBound reports whether a local socket is bound on the given port.
func LocalPortBound(network string, port int) (bool, error) {
	return PortChecker{}.LocalPortBound(network, port)
}

// LocalPortBound reports whether a local socket is bound on the given port.
func (c PortChecker) LocalPortBound(network string, port int) (bool, error) {
	switch network {
	case "tcp", "udp":
	default:
		return false, fmt.Errorf("unsupported network %q", network)
	}
	if port <= 0 || port > 65535 {
		return false, fmt.Errorf("invalid port %d", port)
	}
	return c.localPortBound(network, port)
}
