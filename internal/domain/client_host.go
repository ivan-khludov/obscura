package domain

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

var clientHostPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

// NormalizeClientHost trims whitespace from a client host value.
func NormalizeClientHost(host string) string {
	return strings.TrimSpace(host)
}

// ValidateClientHost checks a per-VPN client connect host (empty means auto-detect).
func ValidateClientHost(host string) error {
	host = NormalizeClientHost(host)
	if host == "" {
		return nil
	}
	if host == "0.0.0.0" || host == "::" {
		return errors.New("client_host cannot be a wildcard listen address")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsUnspecified() {
			return errors.New("client_host cannot be an unspecified address")
		}
		return nil
	}
	if !clientHostPattern.MatchString(host) {
		return fmt.Errorf("invalid client_host %q", host)
	}
	return nil
}
