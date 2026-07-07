package platform

import (
	"fmt"
	"net"
	"strings"
)

// portBoundBindTest checks local port binding state by attempting to bind.
func (c PortChecker) portBoundBindTest(network string, port int) (bool, error) {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	switch network {
	case "tcp":
		ln, err := c.listenTCP("tcp", addr)
		if err == nil {
			_ = ln.Close()
			return false, nil
		}
		if strings.Contains(err.Error(), "address already in use") {
			return true, nil
		}
		return false, err
	case "udp":
		conn, err := c.listenPacket("udp", addr)
		if err == nil {
			_ = conn.Close()
			return false, nil
		}
		if strings.Contains(err.Error(), "address already in use") {
			return true, nil
		}
		return false, err
	default:
		return false, fmt.Errorf("unsupported network %q", network)
	}
}

func (c PortChecker) listenTCP(network, address string) (interface{ Close() error }, error) {
	if c.ListenTCP != nil {
		return c.ListenTCP(network, address)
	}
	return net.Listen(network, address)
}

func (c PortChecker) listenPacket(network, address string) (interface{ Close() error }, error) {
	if c.ListenPacket != nil {
		return c.ListenPacket(network, address)
	}
	return net.ListenPacket(network, address)
}

// BindTest probes whether a port is bound using a bind attempt.
func (c PortChecker) BindTest(network string, port int) (bool, error) {
	return c.portBoundBindTest(network, port)
}
