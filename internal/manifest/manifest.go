// Package manifest tracks resources installed and managed by obscura for uninstall.
package manifest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// DefaultPath is the default manifest file location.
const DefaultPath = "/etc/obscura/manifest.json"

// File describes an installed file tracked for uninstall.
type File struct {
	Path    string `json:"path"`
	Managed bool   `json:"managed"`
}

// SysctlEntry describes a sysctl key/value applied by obscura.
type SysctlEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// FirewallRule describes a firewall rule added by obscura.
type FirewallRule struct {
	Rule string `json:"rule"`
}

// Manifest records all obscura-managed server resources.
type Manifest struct {
	Version       int            `json:"version"`
	SSHPort       int            `json:"ssh_port,omitempty"`
	Binaries      []string       `json:"binaries,omitempty"`
	Files         []File         `json:"files,omitempty"`
	Sysctl        []SysctlEntry  `json:"sysctl,omitempty"`
	FirewallRules []FirewallRule `json:"firewall_rules,omitempty"`
	Services      []string       `json:"services,omitempty"`
	CertPaths     []string       `json:"cert_paths,omitempty"`
}

// Manager loads and persists the install manifest.
type Manager struct {
	mu            sync.Mutex
	path          string
	data          Manifest
	ReadFile      func(name string) ([]byte, error)
	WriteFile     func(name string, data []byte, perm os.FileMode) error
	MkdirAll      func(path string, perm os.FileMode) error
	MarshalIndent func(v any, prefix, indent string) ([]byte, error)
}

func (m *Manager) readFile(name string) ([]byte, error) {
	if m != nil && m.ReadFile != nil {
		return m.ReadFile(name)
	}
	return os.ReadFile(name)
}

func (m *Manager) writeFile(name string, data []byte, perm os.FileMode) error {
	if m != nil && m.WriteFile != nil {
		return m.WriteFile(name, data, perm)
	}
	return os.WriteFile(name, data, perm)
}

func (m *Manager) mkdirAll(path string, perm os.FileMode) error {
	if m != nil && m.MkdirAll != nil {
		return m.MkdirAll(path, perm)
	}
	return os.MkdirAll(path, perm)
}

func (m *Manager) marshalIndent(v any, prefix, indent string) ([]byte, error) {
	if m != nil && m.MarshalIndent != nil {
		return m.MarshalIndent(v, prefix, indent)
	}
	return json.MarshalIndent(v, prefix, indent)
}

// NewManager returns a Manager for the given manifest path.
func NewManager(path string) *Manager {
	if path == "" {
		path = DefaultPath
	}
	return &Manager{path: path, data: Manifest{Version: 1}}
}

// Load reads the manifest from disk if it exists.
func (m *Manager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	raw, err := m.readFile(m.path)
	if os.IsNotExist(err) {
		m.data = Manifest{Version: 1}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	if err := json.Unmarshal(raw, &m.data); err != nil {
		return fmt.Errorf("parse manifest: %w", err)
	}
	return nil
}

// Save writes the manifest to disk.
func (m *Manager) Save() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.mkdirAll(filepath.Dir(m.path), 0o755); err != nil {
		return fmt.Errorf("mkdir manifest dir: %w", err)
	}
	raw, err := m.marshalIndent(m.data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	return m.writeFile(m.path, raw, 0o600)
}

// Data returns a copy of the current manifest.
func (m *Manager) Data() Manifest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.data
}

// SetSSHPort records the configured SSH listen port.
func (m *Manager) SetSSHPort(port int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data.SSHPort = port
}

// SSHPort returns the recorded SSH port, or 0 when unset.
func (m *Manager) SSHPort() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.data.SSHPort
}

// AddBinary records an installed binary path.
func (m *Manager) AddBinary(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data.Binaries = appendUnique(m.data.Binaries, path)
}

// AddFile records a managed file path.
func (m *Manager) AddFile(path string, managed bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, f := range m.data.Files {
		if f.Path == path {
			m.data.Files[i].Managed = managed
			return
		}
	}
	m.data.Files = append(m.data.Files, File{Path: path, Managed: managed})
}

// AddSysctl records a sysctl entry.
func (m *Manager) AddSysctl(key, value string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, e := range m.data.Sysctl {
		if e.Key == key {
			m.data.Sysctl[i].Value = value
			return
		}
	}
	m.data.Sysctl = append(m.data.Sysctl, SysctlEntry{Key: key, Value: value})
}

// AddFirewallRule records a firewall rule.
func (m *Manager) AddFirewallRule(rule string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.data.FirewallRules {
		if r.Rule == rule {
			return
		}
	}
	m.data.FirewallRules = append(m.data.FirewallRules, FirewallRule{Rule: rule})
}

// RemoveFirewallRule removes a firewall rule from the manifest.
func (m *Manager) RemoveFirewallRule(rule string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.data.FirewallRules[:0]
	for _, r := range m.data.FirewallRules {
		if r.Rule != rule {
			out = append(out, r)
		}
	}
	m.data.FirewallRules = out
}

// AddService records a systemd service name.
func (m *Manager) AddService(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data.Services = appendUnique(m.data.Services, name)
}

// AddCertPath records a TLS certificate or key path for uninstall cleanup.
func (m *Manager) AddCertPath(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data.CertPaths = appendUnique(m.data.CertPaths, path)
}

// RemoveCertPath removes a tracked certificate or key path.
func (m *Manager) RemoveCertPath(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.data.CertPaths[:0]
	for _, p := range m.data.CertPaths {
		if p != path {
			out = append(out, p)
		}
	}
	m.data.CertPaths = out
}

// UninstallPlan describes actions for uninstall dry-run or execution.
type UninstallPlan struct {
	StopServices   []string
	RemoveFiles    []string
	RemoveBinaries []string
	RevertSysctl   []SysctlEntry
	RemoveFirewall []string
}

// PlanFullUninstall builds an uninstall plan from the manifest.
func (m *Manager) PlanFullUninstall() UninstallPlan {
	m.mu.Lock()
	defer m.mu.Unlock()
	plan := UninstallPlan{
		StopServices:   append([]string{}, m.data.Services...),
		RevertSysctl:   append([]SysctlEntry{}, m.data.Sysctl...),
		RemoveBinaries: append([]string{}, m.data.Binaries...),
	}
	for _, f := range m.data.Files {
		if f.Managed {
			plan.RemoveFiles = append(plan.RemoveFiles, f.Path)
		}
	}
	plan.RemoveFiles = append(plan.RemoveFiles, m.data.CertPaths...)
	for _, r := range m.data.FirewallRules {
		plan.RemoveFirewall = append(plan.RemoveFirewall, r.Rule)
	}
	return plan
}

// appendUnique appends item to items when it is not already present.
func appendUnique(items []string, item string) []string {
	for _, v := range items {
		if v == item {
			return items
		}
	}
	return append(items, item)
}
