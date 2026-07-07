// Package sshd reads and updates OpenSSH server configuration.
package sshd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	// DefaultPort is the OpenSSH default when Port is not set.
	DefaultPort = 22
	// ConfigPath is the default sshd configuration file on Linux.
	ConfigPath = "/etc/ssh/sshd_config"
)

var reloadUnits = []string{"ssh", "sshd"}

// Config reads and writes sshd configuration files.
type Config struct {
	ReadFile  func(name string) ([]byte, error)
	WriteFile func(name string, data []byte, perm os.FileMode) error
}

func (c *Config) readFile(name string) ([]byte, error) {
	if c != nil && c.ReadFile != nil {
		return c.ReadFile(name)
	}
	return os.ReadFile(name)
}

func (c *Config) writeFile(name string, data []byte, perm os.FileMode) error {
	if c != nil && c.WriteFile != nil {
		return c.WriteFile(name, data, perm)
	}
	return os.WriteFile(name, data, perm)
}

// Runner executes sshd and systemctl commands.
type Runner struct {
	ReloadUnits []string
	RunCommand  func(ctx context.Context, name string, args ...string) ([]byte, error)
}

func (r *Runner) runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	if r != nil && r.RunCommand != nil {
		return r.RunCommand(ctx, name, args...)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

func (r *Runner) reloadUnitsList() []string {
	if r != nil && r.ReloadUnits != nil {
		return r.ReloadUnits
	}
	return reloadUnits
}

// ValidatePort checks that port is a valid listen port for sshd.
func ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("ssh port must be between 1 and 65535, got %d", port)
	}
	return nil
}

// ReadPort returns the configured Port from path, or DefaultPort when unset.
func ReadPort(path string) (int, error) {
	return new(Config).ReadPort(path)
}

// ReadPort returns the configured Port from path, or DefaultPort when unset.
func (c *Config) ReadPort(path string) (int, error) {
	raw, err := c.readFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultPort, nil
		}
		return 0, fmt.Errorf("read sshd config: %w", err)
	}
	port := DefaultPort
	found := false
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "port") {
			continue
		}
		p, err := strconv.Atoi(fields[1])
		if err != nil {
			return 0, fmt.Errorf("invalid Port directive %q", line)
		}
		if err := ValidatePort(p); err != nil {
			return 0, err
		}
		port = p
		found = true
	}
	if !found {
		return DefaultPort, nil
	}
	return port, nil
}

// SetPort updates or adds a top-level Port directive in path.
func SetPort(path string, port int) error {
	return new(Config).SetPort(path, port)
}

// SetPort updates or adds a top-level Port directive in path.
func (c *Config) SetPort(path string, port int) error {
	if err := ValidatePort(port); err != nil {
		return err
	}
	raw, err := c.readFile(path)
	if err != nil {
		return fmt.Errorf("read sshd config: %w", err)
	}
	backup := path + ".obscura.bak"
	if err := c.writeFile(backup, raw, 0o600); err != nil {
		return fmt.Errorf("backup sshd config: %w", err)
	}
	lines := strings.Split(string(raw), "\n")
	replaced := false
	out := make([]string, 0, len(lines)+1)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !replaced && trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			fields := strings.Fields(trimmed)
			if len(fields) >= 2 && strings.EqualFold(fields[0], "port") {
				out = append(out, fmt.Sprintf("Port %d", port))
				replaced = true
				continue
			}
		}
		out = append(out, line)
	}
	if !replaced {
		if len(out) > 0 && out[len(out)-1] != "" {
			out = append(out, "")
		}
		out = append(out, fmt.Sprintf("Port %d", port))
	}
	updated := strings.Join(out, "\n")
	if !strings.HasSuffix(updated, "\n") {
		updated += "\n"
	}
	if err := c.writeFile(path, []byte(updated), 0o644); err != nil {
		_ = c.writeFile(path, raw, 0o644)
		return fmt.Errorf("write sshd config: %w", err)
	}
	return nil
}

// RestoreBackup restores path from path.obscura.bak when present.
func RestoreBackup(path string) error {
	return new(Config).RestoreBackup(path)
}

// RestoreBackup restores path from path.obscura.bak when present.
func (c *Config) RestoreBackup(path string) error {
	backup := path + ".obscura.bak"
	raw, err := c.readFile(backup)
	if err != nil {
		return err
	}
	return c.writeFile(path, raw, 0o644)
}

// TestConfig validates sshd configuration.
func TestConfig(ctx context.Context, path string) error {
	return new(Runner).TestConfig(ctx, path)
}

// TestConfig validates sshd configuration.
func (r *Runner) TestConfig(ctx context.Context, path string) error {
	if path == "" {
		path = ConfigPath
	}
	out, err := r.runCommand(ctx, "sshd", "-t", "-f", path)
	if err != nil {
		return fmt.Errorf("sshd -t: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// Reload reloads the ssh/sshd systemd unit.
func Reload(ctx context.Context) error {
	return new(Runner).Reload(ctx)
}

// Reload reloads the ssh/sshd systemd unit.
func (r *Runner) Reload(ctx context.Context) error {
	var lastErr error
	for _, unit := range r.reloadUnitsList() {
		out, err := r.runCommand(ctx, "systemctl", "reload", unit)
		if err == nil {
			return nil
		}
		lastErr = fmt.Errorf("systemctl reload %s: %s: %w", unit, strings.TrimSpace(string(out)), err)
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("ssh service not found")
}

// ConfigDir returns the directory containing path.
func ConfigDir(path string) string {
	if path == "" {
		path = ConfigPath
	}
	return filepath.Dir(path)
}
