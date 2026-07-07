// Package doctor runs health checks for an obscura-managed server.
package doctor

import (
	"context"
	"fmt"

	"github.com/ivan-khludov/obscura/internal/platform"
	"github.com/ivan-khludov/obscura/internal/sysctl"
)

// CheckStatus describes the result of a single health check.
type CheckStatus string

// Doctor check result statuses.
const (
	StatusOK   CheckStatus = "ok"
	StatusWarn CheckStatus = "warn"
	StatusFail CheckStatus = "fail"
)

// CheckResult holds one diagnostic check outcome.
type CheckResult struct {
	Name    string      `json:"name"`
	Status  CheckStatus `json:"status"`
	Message string      `json:"message"`
}

// ListenCheck describes a runtime listen-port check for one VPN.
type ListenCheck struct {
	VPNName  string
	Protocol string
	Port     int
	Protos   []string
}

// Checker runs server health diagnostics.
type Checker struct {
	SingBoxActive             func(ctx context.Context) (bool, error)
	ReadSysctl                func(key string) (string, error)
	LocalPortBound            func(network string, port int) (bool, error)
	ListenChecks              []ListenCheck
	ExpectedCongestionControl string
	SSHPort                   int
}

func (c *Checker) readSysctl(key string) (string, error) {
	if c.ReadSysctl != nil {
		return c.ReadSysctl(key)
	}
	return sysctl.ReadCurrent(key)
}

func (c *Checker) localPortBound(network string, port int) (bool, error) {
	if c.LocalPortBound != nil {
		return c.LocalPortBound(network, port)
	}
	return platform.LocalPortBound(network, port)
}

// Run executes all configured health checks.
func (c *Checker) Run(ctx context.Context) []CheckResult {
	var results []CheckResult
	results = append(results, c.checkCongestionControl())
	results = append(results, c.checkForwarding())

	singBoxActive := false
	if c.SingBoxActive != nil {
		singBoxResult := c.checkSingBox(ctx)
		results = append(results, singBoxResult)
		singBoxActive = singBoxResult.Status == StatusOK
	}

	for _, check := range c.ListenChecks {
		results = append(results, c.checkListenCheck(check, singBoxActive))
	}
	if c.SSHPort > 0 {
		results = append(results, c.checkSSHPort(c.SSHPort))
	}
	return results
}

// checkCongestionControl verifies that the configured TCP congestion algorithm is active.
func (c *Checker) checkCongestionControl() CheckResult {
	expected := c.ExpectedCongestionControl
	if expected == "" {
		expected = sysctl.DefaultCongestionControl
	}
	val, err := c.readSysctl(sysctl.KeyCongestionControl)
	if err != nil {
		return CheckResult{Name: "congestion", Status: StatusFail, Message: err.Error()}
	}
	if val != expected {
		return CheckResult{Name: "congestion", Status: StatusWarn, Message: fmt.Sprintf("tcp_congestion_control=%s, expected %s", val, expected)}
	}
	return CheckResult{Name: "congestion", Status: StatusOK, Message: fmt.Sprintf("%s enabled", val)}
}

// checkForwarding verifies that IPv4 forwarding is enabled.
func (c *Checker) checkForwarding() CheckResult {
	val, err := c.readSysctl("net.ipv4.ip_forward")
	if err != nil {
		return CheckResult{Name: "ip_forward", Status: StatusFail, Message: err.Error()}
	}
	if val != "1" {
		return CheckResult{Name: "ip_forward", Status: StatusWarn, Message: fmt.Sprintf("ip_forward=%s, expected 1", val)}
	}
	return CheckResult{Name: "ip_forward", Status: StatusOK, Message: "ipv4 forwarding enabled"}
}

// checkSingBox verifies that the sing-box systemd unit is active.
func (c *Checker) checkSingBox(ctx context.Context) CheckResult {
	active, err := c.SingBoxActive(ctx)
	if err != nil {
		return CheckResult{Name: "sing-box", Status: StatusFail, Message: err.Error()}
	}
	if !active {
		return CheckResult{Name: "sing-box", Status: StatusFail, Message: "sing-box service is not active"}
	}
	return CheckResult{Name: "sing-box", Status: StatusOK, Message: "sing-box service is active"}
}

// checkListenCheck performs an internal helper operation.
func (c *Checker) checkListenCheck(check ListenCheck, singBoxActive bool) CheckResult {
	name := fmt.Sprintf("%s:%d", check.VPNName, check.Port)
	if !singBoxActive {
		return CheckResult{
			Name:    name,
			Status:  StatusWarn,
			Message: "runtime check skipped (sing-box not active)",
		}
	}
	for _, proto := range check.Protos {
		result := c.checkBoundPort(name, proto, check.Port)
		if result.Status != StatusOK {
			return result
		}
	}
	proto := check.Protos[0]
	if len(check.Protos) > 1 {
		proto = "tcp+udp"
	}
	return CheckResult{
		Name:    name,
		Status:  StatusOK,
		Message: fmt.Sprintf("%s/%d listening", proto, check.Port),
	}
}

// checkBoundPort performs an internal helper operation.
func (c *Checker) checkBoundPort(name, network string, port int) CheckResult {
	bound, err := c.localPortBound(network, port)
	if err != nil {
		return CheckResult{Name: name, Status: StatusWarn, Message: err.Error()}
	}
	if !bound {
		return CheckResult{
			Name:    name,
			Status:  StatusWarn,
			Message: fmt.Sprintf("%s/%d not listening", network, port),
		}
	}
	return CheckResult{Name: name, Status: StatusOK, Message: ""}
}

// checkSSHPort warns when the configured SSH port is not listening locally.
func (c *Checker) checkSSHPort(port int) CheckResult {
	bound, err := c.localPortBound("tcp", port)
	if err != nil {
		return CheckResult{Name: "ssh_port", Status: StatusWarn, Message: err.Error()}
	}
	if !bound {
		return CheckResult{
			Name:    "ssh_port",
			Status:  StatusWarn,
			Message: fmt.Sprintf("tcp/%d not listening", port),
		}
	}
	return CheckResult{Name: "ssh_port", Status: StatusOK, Message: fmt.Sprintf("tcp/%d listening", port)}
}

// HasFailures reports whether any check failed.
func HasFailures(results []CheckResult) bool {
	for _, r := range results {
		if r.Status == StatusFail {
			return true
		}
	}
	return false
}
