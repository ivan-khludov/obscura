package service

import (
	"context"
	"fmt"

	"github.com/ivan-khludov/obscura/internal/sysctl"
)

// CongestionControl returns the configured TCP congestion control algorithm.
func (s *Service) CongestionControl() string {
	for _, e := range s.manifest.Data().Sysctl {
		if e.Key == sysctl.KeyCongestionControl {
			return e.Value
		}
	}
	return sysctl.DefaultCongestionControl
}

func (s *Service) availableCongestionControls() ([]string, error) {
	if s.congestionLister != nil {
		return s.congestionLister()
	}
	return sysctl.AvailableCongestionControls()
}

// ListCongestionControls returns congestion algorithms supported by the kernel.
func (s *Service) ListCongestionControls() ([]string, error) {
	list, err := s.availableCongestionControls()
	if err != nil {
		return append([]string(nil), sysctl.FallbackCongestionControls...), nil
	}
	return list, nil
}

// SetCongestionControl applies sysctl settings for the given TCP congestion algorithm.
func (s *Service) SetCongestionControl(ctx context.Context, algorithm string) error {
	_ = ctx
	if s.app.DevMode {
		return fmt.Errorf("congestion control requires production mode (not --dev)")
	}
	if err := s.RequireRootForBootstrap(); err != nil {
		return err
	}
	available, err := s.availableCongestionControls()
	if err != nil {
		available = sysctl.FallbackCongestionControls
	}
	if err := sysctl.ValidateCongestionControl(algorithm, available); err != nil {
		return err
	}
	entries := sysctl.Entries(algorithm)
	if err := s.sysctl.Apply(entries); err != nil {
		return fmt.Errorf("apply sysctl: %w", err)
	}
	for _, e := range entries {
		s.manifest.AddSysctl(e.Key, e.Value)
	}
	s.manifest.AddFile(s.sysctl.ConfPath, true)
	return s.manifest.Save()
}
