// Package systemd manages the sing-box systemd unit lifecycle.
package systemd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DefaultUnitName is the systemd unit for sing-box.
const DefaultUnitName = "sing-box.service"

// DefaultUnitPath is the systemd unit file location.
const DefaultUnitPath = "/etc/systemd/system/sing-box.service"

// DefaultBinaryPath is the sing-box binary path referenced by the unit.
const DefaultBinaryPath = "/usr/local/bin/sing-box"

// DefaultConfigPath is the sing-box config path referenced by the unit.
const DefaultConfigPath = "/etc/obscura/sing-box.json"

// UnitTemplate is the systemd unit file content for sing-box.
const UnitTemplate = `[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
Type=simple
ExecStart=%s run -c %s
Restart=on-failure
RestartSec=5s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
`

// Manager executes systemctl commands for sing-box.
type Manager struct {
	UnitName   string
	UnitPath   string
	BinaryPath string
	ConfigPath string
	RunCommand func(ctx context.Context, name string, args ...string) ([]byte, error)
	MkdirAll   func(path string, perm os.FileMode) error
	WriteFile  func(name string, data []byte, perm os.FileMode) error
}

// NewManager returns a Manager with default paths.
func NewManager() *Manager {
	return &Manager{
		UnitName:   DefaultUnitName,
		UnitPath:   DefaultUnitPath,
		BinaryPath: DefaultBinaryPath,
		ConfigPath: DefaultConfigPath,
	}
}

func (m *Manager) mkdirAll(path string, perm os.FileMode) error {
	if m != nil && m.MkdirAll != nil {
		return m.MkdirAll(path, perm)
	}
	return os.MkdirAll(path, perm)
}

func (m *Manager) writeFile(name string, data []byte, perm os.FileMode) error {
	if m != nil && m.WriteFile != nil {
		return m.WriteFile(name, data, perm)
	}
	return os.WriteFile(name, data, perm)
}

func (m *Manager) combinedOutput(ctx context.Context, args ...string) ([]byte, error) {
	if m != nil && m.RunCommand != nil {
		return m.RunCommand(ctx, "systemctl", args...)
	}
	cmd := exec.CommandContext(ctx, "systemctl", args...)
	return cmd.CombinedOutput()
}

// InstallUnit writes and enables the sing-box systemd unit.
func (m *Manager) InstallUnit(ctx context.Context) error {
	content := fmt.Sprintf(UnitTemplate, m.BinaryPath, m.ConfigPath)
	if err := m.mkdirAll(filepath.Dir(m.UnitPath), 0o755); err != nil {
		return fmt.Errorf("mkdir systemd: %w", err)
	}
	if err := m.writeFile(m.UnitPath, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write unit: %w", err)
	}
	if err := m.run(ctx, "daemon-reload"); err != nil {
		return err
	}
	return m.run(ctx, "enable", m.UnitName)
}

// Start starts the sing-box systemd unit.
func (m *Manager) Start(ctx context.Context) error {
	return m.run(ctx, "start", m.UnitName)
}

// Stop stops the sing-box systemd unit.
func (m *Manager) Stop(ctx context.Context) error {
	return m.run(ctx, "stop", m.UnitName)
}

// Reload reloads sing-box by restarting the unit.
func (m *Manager) Reload(ctx context.Context) error {
	return m.run(ctx, "restart", m.UnitName)
}

// IsActive reports whether the sing-box unit is active.
func (m *Manager) IsActive(ctx context.Context) (bool, error) {
	out, err := m.combinedOutput(ctx, "is-active", m.UnitName)
	status := strings.TrimSpace(string(out))
	if status == "active" {
		return true, nil
	}
	if err != nil {
		if status == "inactive" {
			return false, nil
		}
		if status != "" {
			return false, fmt.Errorf("%s", status)
		}
		return false, err
	}
	return false, nil
}

// Disable disables the sing-box systemd unit.
func (m *Manager) Disable(ctx context.Context) error {
	return m.run(ctx, "disable", m.UnitName)
}

// run executes a systemctl command and returns a wrapped error on failure.
func (m *Manager) run(ctx context.Context, args ...string) error {
	out, err := m.combinedOutput(ctx, args...)
	if err != nil {
		return fmt.Errorf("systemctl %s: %s: %s", strings.Join(args, " "), err, string(out))
	}
	return nil
}

// NopManager is a no-op systemd manager for tests and dev mode.
type NopManager struct{}

// Reload is a no-op reload.
func (NopManager) Reload(_ context.Context) error { return nil }

// IsActive always returns false.
func (NopManager) IsActive(_ context.Context) (bool, error) { return false, nil }
