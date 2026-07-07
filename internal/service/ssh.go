package service

import (
	"context"
	"fmt"

	"github.com/ivan-khludov/obscura/internal/sshd"
)

func (s *Service) sshConfigPath() string {
	if s.sshdPath != "" {
		return s.sshdPath
	}
	return sshd.ConfigPath
}

func (s *Service) sshConfig() *sshd.Config {
	if s.sshdCfg != nil {
		return s.sshdCfg
	}
	return new(sshd.Config)
}

func (s *Service) sshRunner() *sshd.Runner {
	if s.sshdRun != nil {
		return s.sshdRun
	}
	return new(sshd.Runner)
}

// SSHPort returns the configured SSH listen port (manifest, sshd_config, or default 22).
func (s *Service) SSHPort() int {
	if port := s.manifest.SSHPort(); port > 0 {
		return port
	}
	port, err := s.sshConfig().ReadPort(s.sshConfigPath())
	if err != nil {
		return sshd.DefaultPort
	}
	return port
}

// vpnUsingPort reports whether an enabled VPN listens on port.
func (s *Service) vpnUsingPort(ctx context.Context, port int) (string, bool) {
	vpns, err := s.store.ListEnabledVPNs(ctx)
	if err != nil {
		return "", false
	}
	for _, v := range vpns {
		if v.Listen.ListenPort == port {
			return v.Name, true
		}
	}
	return "", false
}

// SetSSHPort updates sshd_config, reloads ssh, adjusts firewall, and saves manifest.
func (s *Service) SetSSHPort(ctx context.Context, port int) error {
	if s.app.DevMode {
		return fmt.Errorf("ssh port change requires production mode (not --dev)")
	}
	if err := sshd.ValidatePort(port); err != nil {
		return err
	}
	current := s.SSHPort()
	if port == current {
		return nil
	}
	if name, ok := s.vpnUsingPort(ctx, port); ok {
		return fmt.Errorf("port %d is used by VPN %q; change that VPN's port first", port, name)
	}
	if err := s.RequireRootForBootstrap(); err != nil {
		return err
	}
	path := s.sshConfigPath()
	cfg := s.sshConfig()
	run := s.sshRunner()
	if err := cfg.SetPort(path, port); err != nil {
		return err
	}
	if err := run.TestConfig(ctx, path); err != nil {
		_ = cfg.RestoreBackup(path)
		return err
	}
	if err := run.Reload(ctx); err != nil {
		_ = cfg.RestoreBackup(path)
		_ = run.TestConfig(ctx, path)
		_ = run.Reload(ctx)
		return err
	}
	s.syncSSHFirewall(ctx, current, port)
	s.manifest.SetSSHPort(port)
	s.manifest.AddFile(path, false)
	return s.manifest.Save()
}

// syncSSHFirewall synchronizes runtime state with persistent configuration.
func (s *Service) syncSSHFirewall(ctx context.Context, oldPort, newPort int) {
	if s.firewall == nil || !s.firewall.IsAvailable() {
		return
	}
	oldRule := fmt.Sprintf("%d/tcp", oldPort)
	for _, r := range s.manifest.Data().FirewallRules {
		if r.Rule == oldRule {
			if err := s.firewall.DeleteRule(ctx, oldRule); err == nil {
				s.manifest.RemoveFirewallRule(oldRule)
			}
			break
		}
	}
	if newPort == oldPort {
		return
	}
	rule, err := s.firewall.AllowPort(ctx, newPort, "tcp")
	if err == nil {
		s.manifest.AddFirewallRule(rule)
	}
}

// syncSSHPortFromSystem records the current sshd Port in manifest when unset.
func (s *Service) syncSSHPortFromSystem() {
	if s.manifest.SSHPort() > 0 {
		return
	}
	port, err := s.sshConfig().ReadPort(s.sshConfigPath())
	if err != nil {
		port = sshd.DefaultPort
	}
	s.manifest.SetSSHPort(port)
}
