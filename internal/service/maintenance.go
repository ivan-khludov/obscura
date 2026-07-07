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
	return s.manifest.PlanFullUninstall()
}

// uninstallFull executes a full uninstall using the manifest plan.
func (s *Service) uninstallFull(ctx context.Context, wipeData bool) error {
	plan := s.manifest.PlanFullUninstall()
	for _, svc := range plan.StopServices {
		_ = s.systemd.Stop(ctx)
		_ = s.systemd.Disable(ctx)
		_ = svc
	}
	for _, rule := range plan.RemoveFirewall {
		if s.firewall != nil {
			_ = s.firewall.DeleteRule(ctx, rule)
		}
	}
	for _, path := range plan.RemoveFiles {
		_ = os.Remove(path)
	}
	for _, path := range plan.RemoveBinaries {
		_ = os.Remove(path)
	}
	if err := s.sysctl.Remove(); err != nil {
		return err
	}
	if wipeData {
		return os.RemoveAll(s.app.DataDir)
	}
	return os.Remove(s.app.ManifestPath)
}
