package service

import (
	"context"
	"fmt"
)

// validateUniquePort returns an error when port is already used by another enabled VPN.
func (s *Service) validateUniquePort(ctx context.Context, port int, excludeID int64) error {
	vpns, err := s.store.ListVPNs(ctx)
	if err != nil {
		return err
	}
	for _, v := range vpns {
		if v.ID == excludeID {
			continue
		}
		if v.Enabled && v.Listen.ListenPort == port {
			return fmt.Errorf("port %d already used by vpn %q", port, v.Name)
		}
	}
	return nil
}

// validateVPNListenPort ensures the port is unique among VPNs and not reserved for SSH.
func (s *Service) validateVPNListenPort(ctx context.Context, port int, excludeID int64) error {
	if err := s.validateUniquePort(ctx, port, excludeID); err != nil {
		return err
	}
	if port == s.SSHPort() {
		return fmt.Errorf("port %d is reserved for SSH; choose another port", port)
	}
	return nil
}
