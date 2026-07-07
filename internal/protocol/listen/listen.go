// Package listen provides shared sing-box inbound listen helpers for protocol adapters.
package listen

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/ivan-khludov/obscura/internal/domain"
)

// Validator validates inbound listen options with optional dependency injection.
type Validator struct {
	ResolveIP func(network, host string) (*net.IPAddr, error)
}

func (v *Validator) resolveIP(network, host string) (*net.IPAddr, error) {
	if v != nil && v.ResolveIP != nil {
		return v.ResolveIP(network, host)
	}
	return net.ResolveIPAddr(network, host)
}

// ValidateListen checks common inbound listen options.
func ValidateListen(listen domain.ListenOptions) error {
	return (&Validator{}).ValidateListen(listen)
}

// ValidateListen checks common inbound listen options.
func (v *Validator) ValidateListen(listen domain.ListenOptions) error {
	if listen.Listen == "" {
		return errors.New("listen address is required")
	}
	if listen.ListenPort < 1 || listen.ListenPort > 65535 {
		return fmt.Errorf("listen_port must be between 1 and 65535, got %d", listen.ListenPort)
	}
	if net.ParseIP(listen.Listen) == nil && listen.Listen != "0.0.0.0" && listen.Listen != "::" {
		if _, err := v.resolveIP("ip", listen.Listen); err != nil {
			return fmt.Errorf("invalid listen address: %w", err)
		}
	}
	return ValidateRoutingMark(listen.RoutingMark)
}

// ValidateRoutingMark checks routing mark syntax for decimal or hex values.
func ValidateRoutingMark(mark string) error {
	if mark == "" {
		return nil
	}
	if strings.HasPrefix(mark, "0x") || strings.HasPrefix(mark, "0X") {
		return nil
	}
	if _, err := strconv.ParseUint(mark, 10, 32); err != nil {
		return fmt.Errorf("invalid routing_mark: %w", err)
	}
	return nil
}

// ApplyOptionalFields copies non-empty listen options into an inbound map.
func ApplyOptionalFields(inbound map[string]any, listen domain.ListenOptions) {
	if listen.BindInterface != "" {
		inbound["bind_interface"] = listen.BindInterface
	}
	if listen.RoutingMark != "" {
		inbound["routing_mark"] = parseRoutingMark(listen.RoutingMark)
	}
	if listen.ReuseAddr {
		inbound["reuse_addr"] = true
	}
	if listen.Netns != "" {
		inbound["netns"] = listen.Netns
	}
	if listen.TCPFastOpen {
		inbound["tcp_fast_open"] = true
	}
	if listen.TCPMultiPath {
		inbound["tcp_multi_path"] = true
	}
	if listen.DisableTCPKeepAlive {
		inbound["disable_tcp_keep_alive"] = true
	}
	if listen.TCPKeepAlive != "" {
		inbound["tcp_keep_alive"] = listen.TCPKeepAlive
	}
	if listen.TCPKeepAliveInterval != "" {
		inbound["tcp_keep_alive_interval"] = listen.TCPKeepAliveInterval
	}
	if listen.UDPFragment {
		inbound["udp_fragment"] = true
	}
	if listen.UDPTimeout != "" {
		inbound["udp_timeout"] = listen.UDPTimeout
	}
	if listen.Detour != "" {
		inbound["detour"] = listen.Detour
	}
}

// UsersFromClients builds sing-box user entries from enabled clients.
func UsersFromClients(clients []domain.ClientConfig) []map[string]string {
	users := make([]map[string]string, 0)
	for _, c := range clients {
		if !c.Enabled {
			continue
		}
		users = append(users, map[string]string{
			"username": c.Username,
			"password": c.Password,
		})
	}
	return users
}

// ProxyHost resolves the host used in client URIs.
func ProxyHost(vpn domain.VPNConfig, serverHost string) string {
	if vpn.ClientHost != "" {
		return vpn.ClientHost
	}
	host := serverHost
	if host == "" {
		host = vpn.Listen.Listen
	}
	if host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return host
}

// parseRoutingMark parses protocol or configuration data.
func parseRoutingMark(mark string) any {
	if strings.HasPrefix(mark, "0x") || strings.HasPrefix(mark, "0X") {
		v, err := strconv.ParseUint(mark[2:], 16, 32)
		if err != nil {
			return mark
		}
		return v
	}
	v, err := strconv.ParseUint(mark, 10, 32)
	if err != nil {
		return mark
	}
	return v
}
