package tui_test

import (
	"path/filepath"
	"testing"

	"github.com/ivan-khludov/obscura/internal/config"
	"github.com/ivan-khludov/obscura/internal/firewall"
	"github.com/ivan-khludov/obscura/internal/manifest"
	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/runtime"
	"github.com/ivan-khludov/obscura/internal/service"
	"github.com/ivan-khludov/obscura/internal/singboxcheck"
	"github.com/ivan-khludov/obscura/internal/store"
	"github.com/ivan-khludov/obscura/internal/systemd"
	"github.com/ivan-khludov/obscura/internal/tui"
)

func TestCreateVPNWizardProtocolPicker(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir:      dir,
		DBPath:       filepath.Join(dir, "state.db"),
		ConfigPath:   filepath.Join(dir, "sing-box.json"),
		ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode:      true,
	}
	st, err := store.Open(app.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})

	m := tui.NewModelForTest(app, orchestration.New(svc))
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Loading: true})
	next, _ := m.Update(tui.NewProtocolListMsgForTest(svc.ListProtocols(), nil))
	m2 := next
	if m2.Wizard().Loading {
		t.Fatal("expected loading cleared")
	}
	if m2.Wizard().StepType != tui.StepPicker {
		t.Fatalf("expected picker, got %v", m2.Wizard().StepType)
	}
	if len(m2.Wizard().Picker) < 2 {
		t.Fatalf("expected at least two protocols, got %#v", m2.Wizard().Picker)
	}
	want := []string{"http", "socks5", "shadowsocks", "trojan", "wireguard", "vmess", "vless", "hysteria2", "tuic"}
	if len(m2.Wizard().Picker) != len(want) {
		t.Fatalf("expected %d protocols, got %#v", len(want), m2.Wizard().Picker)
	}
	for i, name := range want {
		if m2.Wizard().Picker[i] != name {
			t.Fatalf("index %d: got %q want %q", i, m2.Wizard().Picker[i], name)
		}
	}
}

// TestCreateVPNWizardWireguardPortDefault verifies WireGuard wizard defaults to port 51820.

func TestCongestionListMsgClearsLoading(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardSetCongestion, Loading: true})
	next, _ := m.Update(tui.NewCongestionListMsgForTest([]string{"bbr", "cubic"}, "bbr", nil))
	m2 := next
	if m2.Wizard().Loading {
		t.Fatal("expected loading cleared")
	}
	if m2.Wizard().StepType != tui.StepPicker {
		t.Fatalf("expected picker, got %v", m2.Wizard().StepType)
	}
	if len(m2.Wizard().Picker) != 2 {
		t.Fatalf("unexpected Picker: %#v", m2.Wizard().Picker)
	}
}

// TestMenuStatusMsgRebuildsMainMenu applies bootstrap state to menu items.

func TestLoadVPNsCmdForTest(t *testing.T) {
	m, svc := newTestServiceModel(t)
	orch := orchestration.New(svc)
	msg := firstTeaMsg(tui.LoadVPNsCmdForTest(orch))
	if msg == nil {
		t.Fatal("expected vpn list msg")
	}
	_ = m
}

func TestLoadClientsCmdForTest(t *testing.T) {
	_, svc := newTestServiceModel(t)
	createTestVPN(t, svc, "main", 1080)
	orch := orchestration.New(svc)
	msg := firstTeaMsg(tui.LoadClientsCmdForTest(orch, "main"))
	if msg == nil {
		t.Fatal("expected client list msg")
	}
}

func TestLoadBackupsCmdForTest(t *testing.T) {
	_, svc := newTestServiceModel(t)
	msg := firstTeaMsg(tui.LoadBackupsCmdForTest(orchestration.New(svc)))
	if msg == nil {
		t.Fatal("expected backup list msg")
	}
}

func TestLoadCongestionCmdForTest(t *testing.T) {
	_, svc := newTestServiceModel(t)
	msg := firstTeaMsg(tui.LoadCongestionCmdForTest(orchestration.New(svc)))
	if msg == nil {
		t.Fatal("expected congestion list msg")
	}
}

func TestLoadProtocolsCmdForTest(t *testing.T) {
	_, svc := newTestServiceModel(t)
	msg := firstTeaMsg(tui.LoadProtocolsCmdForTest(orchestration.New(svc)))
	if msg == nil {
		t.Fatal("expected protocol list msg")
	}
}
