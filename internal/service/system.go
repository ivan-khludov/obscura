package service

import (
	"context"
	"fmt"

	"github.com/ivan-khludov/obscura/internal/doctor"
	"github.com/ivan-khludov/obscura/internal/fallback"
	"github.com/ivan-khludov/obscura/internal/platform"
	"github.com/ivan-khludov/obscura/internal/systemd"
	"github.com/ivan-khludov/obscura/internal/version"
)

// StatusSummary describes the current obscura runtime state.
type StatusSummary struct {
	ObscuraVersion    string `json:"obscura_version"`
	DataDir           string `json:"data_dir"`
	ConfigPath        string `json:"config_path"`
	SingBoxActive     bool   `json:"sing_box_active"`
	VPNCount          int    `json:"vpn_count"`
	ClientCount       int    `json:"client_count"`
	CongestionControl string `json:"congestion_control"`
	SSHPort           int    `json:"ssh_port"`
}

// Status returns a summary of obscura state.
func (s *Service) Status(ctx context.Context) (*StatusSummary, error) {
	active, _ := s.systemd.IsActive(ctx)
	vpns, err := s.store.ListVPNs(ctx)
	if err != nil {
		return nil, err
	}
	clients := 0
	for _, v := range vpns {
		list, err := s.store.ListClientsByVPN(ctx, v.ID)
		if err != nil {
			return nil, err
		}
		clients += len(list)
	}
	return &StatusSummary{
		ObscuraVersion:    version.Version,
		DataDir:           s.app.DataDir,
		ConfigPath:        s.app.ConfigPath,
		SingBoxActive:     active,
		VPNCount:          len(vpns),
		ClientCount:       clients,
		CongestionControl: s.CongestionControl(),
		SSHPort:           s.SSHPort(),
	}, nil
}

// Doctor runs health checks including sing-box and VPN listen ports.
func (s *Service) Doctor(ctx context.Context) []doctor.CheckResult {
	checks := s.buildListenChecks(ctx)
	checker := doctor.Checker{
		SingBoxActive:             s.systemd.IsActive,
		ListenChecks:              checks,
		ExpectedCongestionControl: s.CongestionControl(),
		SSHPort:                   s.SSHPort(),
	}
	results := checker.Run(ctx)
	if s.needsFallbackStub(ctx) {
		results = append(results, s.checkFallbackStub(ctx))
	}
	return results
}

// needsFallbackStub reports whether a protocol or VPN uses a feature.
func (s *Service) needsFallbackStub(ctx context.Context) bool {
	vpns, err := s.store.ListVPNs(ctx)
	if err != nil {
		return false
	}
	for _, vpn := range vpns {
		if usesLocalFallbackStub(vpn) {
			return true
		}
	}
	return false
}

// checkFallbackStub performs an internal helper operation.
func (s *Service) checkFallbackStub(ctx context.Context) doctor.CheckResult {
	activeFn := fallback.IsActive
	if s.fallbackActive != nil {
		activeFn = s.fallbackActive
	}
	active, err := activeFn(ctx)
	if err != nil {
		return doctor.CheckResult{Name: "fallback_stub", Status: doctor.StatusFail, Message: err.Error()}
	}
	if !active {
		return doctor.CheckResult{
			Name:    "fallback_stub",
			Status:  doctor.StatusWarn,
			Message: fmt.Sprintf("VPN fallback targets %s:%d but %s is not active", fallback.DefaultServer, fallback.DefaultPort, fallback.UnitName),
		}
	}
	return doctor.CheckResult{Name: "fallback_stub", Status: doctor.StatusOK, Message: "fallback stub service active"}
}

// IsBootstrapped reports whether obscura bootstrap has completed.
func (s *Service) IsBootstrapped() bool {
	for _, svc := range s.manifest.Data().Services {
		if svc == systemd.DefaultUnitName {
			return true
		}
	}
	return false
}

// RequireRootForBootstrap returns an error when bootstrap runs without root outside dev mode.
func (s *Service) RequireRootForBootstrap() error {
	if s.app.DevMode {
		return nil
	}
	isRoot := platform.IsRoot
	if s.rootCheck != nil {
		isRoot = s.rootCheck
	}
	if !isRoot() {
		return fmt.Errorf("bootstrap requires root privileges")
	}
	return nil
}
