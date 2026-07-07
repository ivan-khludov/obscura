//go:build linux

package platform

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

// localPortBound checks local port binding state.
func (c PortChecker) localPortBound(network string, port int) (bound bool, err error) {
	path := "/proc/net/tcp"
	if network == "udp" {
		path = "/proc/net/udp"
	}
	f, err := c.openFile(path)
	if err != nil {
		return c.portBoundBindTest(network, port)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	wantPort := fmt.Sprintf("%04X", port)
	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return false, scanner.Err()
	}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		localPort, ok := parseProcNetLocalPort(fields[1])
		if !ok || localPort != wantPort {
			continue
		}
		if network == "tcp" {
			if fields[3] == "0A" {
				return true, nil
			}
			continue
		}
		return true, nil
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	return false, nil
}

// parseProcNetLocalPort parses the local port hex field from /proc/net/* lines.
func parseProcNetLocalPort(localAddr string) (string, bool) {
	parts := strings.SplitN(localAddr, ":", 2)
	if len(parts) != 2 {
		return "", false
	}
	portHex := strings.ToUpper(parts[1])
	if _, err := strconv.ParseUint(portHex, 16, 16); err != nil {
		return "", false
	}
	return portHex, true
}
