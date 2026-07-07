//go:build !linux

package platform

// localPortBound checks local port binding state.
func (c PortChecker) localPortBound(network string, port int) (bool, error) {
	return c.portBoundBindTest(network, port)
}
