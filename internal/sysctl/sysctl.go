// Package sysctl applies and reverts kernel tuning managed by obscura.
package sysctl

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DefaultConfPath is the sysctl drop-in file written by obscura bootstrap.
const DefaultConfPath = "/etc/sysctl.d/99-obscura.conf"

// DefaultCongestionControl is the TCP congestion algorithm applied at bootstrap.
const DefaultCongestionControl = "bbr"

// KeyCongestionControl is the sysctl key for TCP congestion control.
const KeyCongestionControl = "net.ipv4.tcp_congestion_control"

// KeyDefaultQdisc is the sysctl key for the default queue discipline.
const KeyDefaultQdisc = "net.core.default_qdisc"

// FallbackCongestionControls is used when the kernel availability list cannot be read.
var FallbackCongestionControls = []string{"cubic", "bbr", "htcp", "reno"}

// Entry describes a sysctl key and value pair.
type Entry struct {
	Key   string
	Value string
}

// Reader reads sysctl values from /proc/sys.
type Reader struct {
	ReadFile func(name string) ([]byte, error)
}

func (r *Reader) readFile(name string) ([]byte, error) {
	if r != nil && r.ReadFile != nil {
		return r.ReadFile(name)
	}
	return os.ReadFile(name)
}

// DefaultEntries returns forwarding and default TCP congestion settings for VPN servers.
func DefaultEntries() []Entry {
	return Entries(DefaultCongestionControl)
}

// Entries returns sysctl settings for the given TCP congestion control algorithm.
func Entries(congestionControl string) []Entry {
	cc := strings.TrimSpace(congestionControl)
	if cc == "" {
		cc = DefaultCongestionControl
	}
	return []Entry{
		{Key: "net.ipv4.ip_forward", Value: "1"},
		{Key: KeyCongestionControl, Value: cc},
		{Key: KeyDefaultQdisc, Value: DefaultQdiscFor(cc)},
	}
}

// DefaultQdiscFor returns a queue discipline paired with the congestion algorithm.
func DefaultQdiscFor(congestionControl string) string {
	if congestionControl == "bbr" {
		return "fq"
	}
	return "fq_codel"
}

// AvailableCongestionControls reads algorithms supported by the running kernel.
func AvailableCongestionControls() ([]string, error) {
	return new(Reader).AvailableCongestionControls()
}

// AvailableCongestionControls reads algorithms supported by the running kernel.
func (r *Reader) AvailableCongestionControls() ([]string, error) {
	raw, err := r.ReadCurrent("net.ipv4.tcp_available_congestion_control")
	if err != nil {
		return nil, err
	}
	parts := strings.Fields(raw)
	if len(parts) == 0 {
		return nil, fmt.Errorf("no congestion control algorithms reported")
	}
	return parts, nil
}

// ValidateCongestionControl reports whether name is in the available list.
func ValidateCongestionControl(name string, available []string) error {
	for _, a := range available {
		if a == name {
			return nil
		}
	}
	return fmt.Errorf("unsupported congestion control %q", name)
}

// Manager writes and reverts sysctl configuration.
type Manager struct {
	ConfPath   string
	Reload     func() error
	MkdirAll   func(path string, perm os.FileMode) error
	WriteFile  func(name string, data []byte, perm os.FileMode) error
	RemoveFile func(name string) error
}

// NewManager returns a Manager with the default conf path.
func NewManager() *Manager {
	return &Manager{ConfPath: DefaultConfPath}
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

func (m *Manager) removeFile(name string) error {
	if m != nil && m.RemoveFile != nil {
		return m.RemoveFile(name)
	}
	return os.Remove(name)
}

// Apply writes sysctl entries to the drop-in file and runs sysctl --system.
func (m *Manager) Apply(entries []Entry) error {
	var b strings.Builder
	for _, e := range entries {
		b.WriteString(e.Key)
		b.WriteString(" = ")
		b.WriteString(e.Value)
		b.WriteString("\n")
	}
	if err := m.mkdirAll(filepath.Dir(m.ConfPath), 0o755); err != nil {
		return fmt.Errorf("mkdir sysctl.d: %w", err)
	}
	if err := m.writeFile(m.ConfPath, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("write sysctl conf: %w", err)
	}
	return m.reloadSystem()
}

// Remove deletes the obscura sysctl drop-in file and reloads sysctl settings.
func (m *Manager) Remove() error {
	if err := m.removeFile(m.ConfPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove sysctl conf: %w", err)
	}
	return m.reloadSystem()
}

// reloadSystem applies sysctl configuration from disk.
func (m *Manager) reloadSystem() error {
	if m.Reload != nil {
		return m.Reload()
	}
	cmd := exec.Command("sysctl", "--system")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sysctl --system: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// ReadCurrent reads a sysctl value from /proc/sys.
func ReadCurrent(key string) (string, error) {
	return new(Reader).ReadCurrent(key)
}

// ReadCurrent reads a sysctl value from /proc/sys.
func (r *Reader) ReadCurrent(key string) (string, error) {
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	raw, err := r.readFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", key, err)
	}
	return strings.TrimSpace(string(raw)), nil
}
