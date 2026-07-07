package manifest_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/manifest"
)

func TestNewManager_defaultPath(t *testing.T) {
	m := manifest.NewManager("")
	if m == nil {
		t.Fatal("expected manager")
	}
}

func TestLoad_missingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	m := manifest.NewManager(path)
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	if m.Data().Version != 1 {
		t.Fatalf("version = %d, want 1", m.Data().Version)
	}
}

func TestLoad_success(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	initial := manifest.Manifest{Version: 1, SSHPort: 22}
	raw, err := json.Marshal(initial)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	m := manifest.NewManager(path)
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	if m.SSHPort() != 22 {
		t.Fatalf("ssh port = %d", m.SSHPort())
	}
}

func TestLoad_readError(t *testing.T) {
	m := &manifest.Manager{
		ReadFile: func(string) ([]byte, error) {
			return nil, errors.New("read failed")
		},
	}
	if err := m.Load(); err == nil || !strings.Contains(err.Error(), "read manifest") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoad_parseError(t *testing.T) {
	m := &manifest.Manager{
		ReadFile: func(string) ([]byte, error) {
			return []byte("{"), nil
		},
	}
	if err := m.Load(); err == nil || !strings.Contains(err.Error(), "parse manifest") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSave_roundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "manifest.json")
	m := manifest.NewManager(path)
	m.SetSSHPort(2222)
	m.AddBinary("/usr/local/bin/sing-box")
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	loaded := manifest.NewManager(path)
	if err := loaded.Load(); err != nil {
		t.Fatal(err)
	}
	if loaded.SSHPort() != 2222 {
		t.Fatalf("ssh port = %d", loaded.SSHPort())
	}
}

func TestSave_mkdirError(t *testing.T) {
	m := &manifest.Manager{
		MkdirAll: func(string, os.FileMode) error {
			return errors.New("mkdir failed")
		},
	}
	if err := m.Save(); err == nil || !strings.Contains(err.Error(), "mkdir manifest dir") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSave_writeError(t *testing.T) {
	m := &manifest.Manager{
		MkdirAll: func(string, os.FileMode) error { return nil },
		WriteFile: func(string, []byte, os.FileMode) error {
			return errors.New("write failed")
		},
	}
	if err := m.Save(); err == nil || !strings.Contains(err.Error(), "write failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSave_marshalError(t *testing.T) {
	m := &manifest.Manager{
		MkdirAll: func(string, os.FileMode) error { return nil },
		MarshalIndent: func(any, string, string) ([]byte, error) {
			return nil, errors.New("marshal failed")
		},
	}
	if err := m.Save(); err == nil || !strings.Contains(err.Error(), "marshal manifest") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestData(t *testing.T) {
	m := manifest.NewManager(filepath.Join(t.TempDir(), "manifest.json"))
	m.AddService("sing-box.service")
	data := m.Data()
	if len(data.Services) != 1 {
		t.Fatalf("services = %#v", data.Services)
	}
	m.AddService("other.service")
	if len(data.Services) != 1 {
		t.Fatal("expected copy, not live view")
	}
}

func TestSSHPort(t *testing.T) {
	m := manifest.NewManager(filepath.Join(t.TempDir(), "manifest.json"))
	if m.SSHPort() != 0 {
		t.Fatalf("expected 0, got %d", m.SSHPort())
	}
	m.SetSSHPort(22)
	if m.SSHPort() != 22 {
		t.Fatalf("expected 22, got %d", m.SSHPort())
	}
}

func TestAddBinary_deduplicates(t *testing.T) {
	m := manifest.NewManager(filepath.Join(t.TempDir(), "manifest.json"))
	m.AddBinary("/usr/local/bin/sing-box")
	m.AddBinary("/usr/local/bin/sing-box")
	plan := m.PlanFullUninstall()
	if len(plan.RemoveBinaries) != 1 {
		t.Fatalf("binaries = %#v", plan.RemoveBinaries)
	}
}

func TestAddFile_updateExisting(t *testing.T) {
	m := manifest.NewManager(filepath.Join(t.TempDir(), "manifest.json"))
	m.AddFile("/etc/obscura/sing-box.json", false)
	m.AddFile("/etc/obscura/sing-box.json", true)
	plan := m.PlanFullUninstall()
	if len(plan.RemoveFiles) != 1 {
		t.Fatalf("files = %#v", plan.RemoveFiles)
	}
}

func TestAddFile_unmanagedSkipped(t *testing.T) {
	m := manifest.NewManager(filepath.Join(t.TempDir(), "manifest.json"))
	m.AddFile("/etc/obscura/state.db", false)
	plan := m.PlanFullUninstall()
	if len(plan.RemoveFiles) != 0 {
		t.Fatalf("files = %#v", plan.RemoveFiles)
	}
}

func TestAddSysctl_updateExisting(t *testing.T) {
	m := manifest.NewManager(filepath.Join(t.TempDir(), "manifest.json"))
	m.AddSysctl("net.ipv4.ip_forward", "0")
	m.AddSysctl("net.ipv4.ip_forward", "1")
	plan := m.PlanFullUninstall()
	if len(plan.RevertSysctl) != 1 || plan.RevertSysctl[0].Value != "1" {
		t.Fatalf("sysctl = %#v", plan.RevertSysctl)
	}
}

func TestAddFirewallRule_deduplicates(t *testing.T) {
	m := manifest.NewManager(filepath.Join(t.TempDir(), "manifest.json"))
	m.AddFirewallRule("1080/tcp")
	m.AddFirewallRule("1080/tcp")
	plan := m.PlanFullUninstall()
	if len(plan.RemoveFirewall) != 1 {
		t.Fatalf("rules = %#v", plan.RemoveFirewall)
	}
}

func TestRemoveFirewallRule(t *testing.T) {
	m := manifest.NewManager(filepath.Join(t.TempDir(), "manifest.json"))
	m.AddFirewallRule("1080/tcp")
	m.AddFirewallRule("1081/tcp")
	m.RemoveFirewallRule("1080/tcp")
	plan := m.PlanFullUninstall()
	if len(plan.RemoveFirewall) != 1 || plan.RemoveFirewall[0] != "1081/tcp" {
		t.Fatalf("unexpected firewall rules: %#v", plan.RemoveFirewall)
	}
}

func TestAddService_deduplicates(t *testing.T) {
	m := manifest.NewManager(filepath.Join(t.TempDir(), "manifest.json"))
	m.AddService("sing-box.service")
	m.AddService("sing-box.service")
	plan := m.PlanFullUninstall()
	if len(plan.StopServices) != 1 {
		t.Fatalf("services = %#v", plan.StopServices)
	}
}

func TestCertPaths(t *testing.T) {
	m := manifest.NewManager(filepath.Join(t.TempDir(), "manifest.json"))
	m.AddCertPath("/etc/obscura/cert.pem")
	m.AddCertPath("/etc/obscura/cert.pem")
	m.AddCertPath("/etc/obscura/key.pem")
	m.RemoveCertPath("/etc/obscura/cert.pem")
	plan := m.PlanFullUninstall()
	if len(plan.RemoveFiles) != 1 || plan.RemoveFiles[0] != "/etc/obscura/key.pem" {
		t.Fatalf("files = %#v", plan.RemoveFiles)
	}
}

func TestPlanFullUninstall(t *testing.T) {
	m := manifest.NewManager(filepath.Join(t.TempDir(), "manifest.json"))
	m.AddBinary("/usr/local/bin/sing-box")
	m.AddFile("/etc/obscura/sing-box.json", true)
	m.AddSysctl("net.ipv4.tcp_congestion_control", "bbr")
	m.AddFirewallRule("1080/tcp")
	m.AddService("sing-box.service")
	m.AddCertPath("/etc/obscura/cert.pem")
	plan := m.PlanFullUninstall()
	if len(plan.RemoveBinaries) != 1 {
		t.Fatalf("expected 1 binary, got %d", len(plan.RemoveBinaries))
	}
	if len(plan.RemoveFiles) != 2 {
		t.Fatalf("expected 2 files, got %d", len(plan.RemoveFiles))
	}
	if len(plan.RevertSysctl) != 1 {
		t.Fatalf("expected 1 sysctl, got %d", len(plan.RevertSysctl))
	}
	if len(plan.RemoveFirewall) != 1 {
		t.Fatalf("expected 1 firewall rule, got %d", len(plan.RemoveFirewall))
	}
	if len(plan.StopServices) != 1 {
		t.Fatalf("expected 1 service, got %d", len(plan.StopServices))
	}
}

func TestSave_defaultFS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	m := manifest.NewManager(path)
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
}

func TestLoad_defaultFS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	m := manifest.NewManager(path)
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
}
