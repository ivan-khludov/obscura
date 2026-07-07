package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ivan-khludov/obscura/internal/fallback"
	"github.com/ivan-khludov/obscura/internal/install"
	"github.com/ivan-khludov/obscura/internal/sysctl"
	"github.com/ivan-khludov/obscura/internal/systemd"
)

// EnableBootstrapFirewall opens SSH in ufw and activates the firewall during bootstrap.
func (s *Service) EnableBootstrapFirewall(ctx context.Context, opts BootstrapOptions) error {
	if s.firewall == nil || !s.firewall.IsAvailable() {
		return nil
	}
	reportBootstrapProgress(opts, "Enabling firewall…", 14)
	s.syncSSHPortFromSystem()
	sshPort := s.SSHPort()
	if err := s.firewall.Enable(ctx, sshPort); err != nil {
		return fmt.Errorf("enable firewall: %w", err)
	}
	s.manifest.AddFirewallRule(fmt.Sprintf("%d/tcp", sshPort))
	return nil
}

// bootstrap initializes obscura directories, sysctl, sing-box, and systemd.
func (s *Service) bootstrap(ctx context.Context, opts BootstrapOptions) error {
	reportBootstrapProgress(opts, "Checking privileges…", 1)
	if err := s.RequireRootForBootstrap(); err != nil {
		return err
	}
	reportBootstrapProgress(opts, "Creating directories…", 5)
	dirs := []string{
		s.app.DataDir,
		filepath.Join(s.app.DataDir, "keys"),
		filepath.Join(s.app.DataDir, "certs"),
		filepath.Join(s.app.DataDir, "backups"),
		filepath.Join(s.app.DataDir, "history"),
		filepath.Join(s.app.DataDir, "cache"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}
	entries := sysctl.DefaultEntries()
	if !s.app.DevMode {
		reportBootstrapProgress(opts, "Applying kernel tuning…", 12)
		if err := s.sysctl.Apply(entries); err != nil {
			return err
		}
		for _, e := range entries {
			s.manifest.AddSysctl(e.Key, e.Value)
		}
		s.manifest.AddFile(s.sysctl.ConfPath, true)
	}
	if !s.app.DevMode {
		if err := s.EnableBootstrapFirewall(ctx, opts); err != nil {
			return err
		}
	}
	if !s.app.DevMode {
		reportBootstrapProgress(opts, "Installing sing-box…", 15)
		var version string
		var err error
		onInstallProgress := func(read, total int64) {
			label := formatDownloadProgress(read, total)
			percent := 15
			if total > 0 {
				percent = 15 + int(read*55/total)
			}
			reportBootstrapProgress(opts, label, percent)
		}
		if s.installFn != nil {
			version, err = s.installFn(install.DefaultInstallPath, onInstallProgress)
		} else {
			version, err = s.installer.Install(install.DefaultInstallPath, onInstallProgress)
		}
		if err != nil {
			return fmt.Errorf("install sing-box: %w", err)
		}
		s.manifest.AddBinary(install.DefaultInstallPath)
		_ = version
		reportBootstrapProgress(opts, "sing-box installed", 72)
	}
	reportBootstrapProgress(opts, "Installing systemd unit…", 78)
	if err := s.systemd.InstallUnit(ctx); err != nil && !s.app.DevMode {
		return err
	}
	s.manifest.AddFile(systemd.DefaultUnitPath, true)
	s.manifest.AddService(systemd.DefaultUnitName)
	s.manifest.AddFile(s.app.ConfigPath, true)
	reportBootstrapProgress(opts, "Saving manifest…", 84)
	if err := s.manifest.Save(); err != nil {
		return err
	}
	reportBootstrapProgress(opts, "Writing configuration…", 90)
	if err := s.writeInitialConfig(ctx); err != nil {
		return err
	}
	if !s.app.DevMode {
		reportBootstrapProgress(opts, "Starting sing-box…", 96)
		if err := s.systemd.Start(ctx); err != nil {
			return err
		}
	}
	if opts.WithFallbackStub {
		reportBootstrapProgress(opts, "Installing fallback stub…", 98)
		var err error
		if s.fallbackInstall != nil {
			err = s.fallbackInstall(ctx)
		} else {
			installer := fallback.Installer{DevMode: s.app.DevMode, DataDir: s.app.DataDir}
			err = installer.Install(ctx)
		}
		if err != nil {
			return fmt.Errorf("install fallback stub: %w", err)
		}
		s.manifest.AddService(fallback.UnitName)
		if !s.app.DevMode {
			s.manifest.AddFile(fallback.UnitPath, true)
			s.manifest.AddFile(fallback.InstallDir, false)
		}
		if err := s.manifest.Save(); err != nil {
			return err
		}
	}
	reportBootstrapProgress(opts, "Bootstrap complete", 100)
	return nil
}

// writeInitialConfig performs an internal helper operation.
func (s *Service) writeInitialConfig(ctx context.Context) error {
	data, err := s.renderer.Render(ctx)
	if err != nil {
		return fmt.Errorf("render initial config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.app.ConfigPath), 0o755); err != nil {
		return fmt.Errorf("mkdir config dir: %w", err)
	}
	if err := os.WriteFile(s.app.ConfigPath, data, 0o600); err != nil {
		return fmt.Errorf("write initial config: %w", err)
	}
	if !s.app.DevMode && s.checker != nil {
		if err := s.checker.Check(ctx, s.app.ConfigPath); err != nil {
			return fmt.Errorf("sing-box check initial config: %w", err)
		}
	}
	return nil
}
