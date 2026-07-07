package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/ivan-khludov/obscura/internal/backup"
	"github.com/ivan-khludov/obscura/internal/manifest"
)

// createBackup archives state.db, sing-box.json, and manifest.json.
func (s *Service) createBackup(ctx context.Context) (string, error) {
	_ = ctx
	backupDir := filepath.Join(s.app.DataDir, "backups")
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		return "", err
	}
	dest := filepath.Join(backupDir, backup.DefaultBackupName())
	sources := []string{s.app.DBPath, s.app.ConfigPath, s.app.ManifestPath}
	if err := backup.Create(dest, sources); err != nil {
		return "", err
	}
	return dest, nil
}

// listBackups returns backup archives sorted newest first.
func (s *Service) listBackups(ctx context.Context) ([]BackupEntry, error) {
	_ = ctx
	dir := filepath.Join(s.app.DataDir, "backups")
	glob := filepath.Glob
	if s.backupGlob != nil {
		glob = s.backupGlob
	}
	matches, err := glob(filepath.Join(dir, "*.tar.gz"))
	if err != nil {
		return nil, fmt.Errorf("list backups: %w", err)
	}
	entries := make([]BackupEntry, 0, len(matches))
	for _, path := range matches {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		entries = append(entries, BackupEntry{
			Name:    filepath.Base(path),
			Path:    path,
			ModTime: info.ModTime(),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ModTime.After(entries[j].ModTime)
	})
	return entries, nil
}

// restoreBackup extracts a backup archive, validates sing-box config, and reloads the service.
// Restart the obscura process after restore so SQLite state is reloaded from disk.
func (s *Service) restoreBackup(ctx context.Context, archivePath string) error {
	if err := backup.Restore(archivePath, s.app.DataDir); err != nil {
		return err
	}
	if s.checker != nil {
		if err := s.checker.Check(ctx, s.app.ConfigPath); err != nil {
			return fmt.Errorf("sing-box check after restore: %w", err)
		}
	}
	if s.systemdMgr != nil {
		if err := s.systemdMgr.Reload(ctx); err != nil {
			return fmt.Errorf("reload sing-box after restore: %w", err)
		}
	}
	return nil
}

// uninstallPlan returns the full uninstall plan from manifest.
func (s *Service) uninstallPlan() manifest.UninstallPlan {
	return s.sanitizeUninstallPlan(s.manifest.PlanFullUninstall())
}

// sanitizeUninstallPlan drops the SSH firewall rule (never removed, to keep the
// session alive) and appends the obscura binary itself so a full uninstall
// leaves nothing behind.
func (s *Service) sanitizeUninstallPlan(plan manifest.UninstallPlan) manifest.UninstallPlan {
	sshPort := s.SSHPort()
	rules := plan.RemoveFirewall[:0:0]
	for _, rule := range plan.RemoveFirewall {
		if isSSHFirewallRule(rule, sshPort) {
			continue
		}
		rules = append(rules, rule)
	}
	plan.RemoveFirewall = rules
	if path, ok := s.obscuraBinaryPath(); ok {
		plan.RemoveBinaries = append(plan.RemoveBinaries, path)
	}
	return plan
}

// obscuraBinaryPath resolves the running obscura binary path for removal during
// a full uninstall. It is disabled in dev mode so tests and local builds are
// never deleted.
func (s *Service) obscuraBinaryPath() (string, bool) {
	if s.app.DevMode {
		return "", false
	}
	self := s.selfExecutable
	if self == nil {
		self = os.Executable
	}
	path, err := self()
	if err != nil {
		return "", false
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	return path, true
}

// uninstallFull executes a full uninstall using the manifest plan.
func (s *Service) uninstallFull(ctx context.Context, wipeData bool) error {
	plan := s.sanitizeUninstallPlan(s.manifest.PlanFullUninstall())
	for _, svc := range plan.StopServices {
		_ = s.systemd.Stop(ctx)
		_ = s.systemd.Disable(ctx)
		_ = svc
	}
	// Re-assert SSH allow before ufw reloads so DeleteRule cannot drop the session.
	s.ensureSSHFirewallAllowed(ctx)
	sshPort := s.SSHPort()
	for _, rule := range plan.RemoveFirewall {
		if isSSHFirewallRule(rule, sshPort) {
			continue
		}
		if s.firewall != nil {
			_ = s.firewall.DeleteRule(ctx, rule)
		}
	}
	if err := s.sshKeepalive().Remove(ctx); err != nil {
		return err
	}
	for _, path := range plan.RemoveFiles {
		_ = os.Remove(path)
	}
	obscuraBin, removeObscura := s.obscuraBinaryPath()
	for _, path := range plan.RemoveBinaries {
		if removeObscura && path == obscuraBin {
			continue
		}
		_ = os.Remove(path)
	}
	if err := s.sysctl.Remove(); err != nil {
		return err
	}
	if wipeData {
		if err := os.RemoveAll(s.app.DataDir); err != nil {
			return err
		}
	} else if err := os.Remove(s.app.ManifestPath); err != nil {
		return err
	}
	// Remove the obscura binary last; on Linux deleting a running executable is safe.
	if removeObscura {
		if err := os.Remove(obscuraBin); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
