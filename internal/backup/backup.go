// Package backup creates and restores obscura state archives.
package backup

import (
	"fmt"
	"time"
)

var defaultArchiver = NewArchiver(NewOSFileSystem())

// Create builds a gzip tar archive of the given paths into destPath.
func Create(destPath string, sources []string) error {
	return defaultArchiver.Create(destPath, sources)
}

// DefaultBackupName returns a timestamped backup filename.
func DefaultBackupName() string {
	return fmt.Sprintf("obscura-backup-%s.tar.gz", time.Now().UTC().Format("20060102-150405"))
}

// Restore extracts a backup archive into destDir.
func Restore(archivePath, destDir string) error {
	return defaultArchiver.Restore(archivePath, destDir)
}
