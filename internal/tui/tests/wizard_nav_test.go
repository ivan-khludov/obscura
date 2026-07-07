package tui_test

import (
	"path/filepath"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
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

func TestSSHPortWizardStart(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir:      dir,
		ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode:      true,
	}
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	man.SetSSHPort(2222)
	_ = man.Save()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	m := tui.NewModelForTest(app, orchestration.New(svc))
	next, cmd := m.StartSSHPortWizard()
	if next.Wizard().Kind != tui.WizardSetSSHPort {
		t.Fatalf("expected tui.WizardSetSSHPort, got %v", next.Wizard().Kind)
	}
	if next.Wizard().StepType != tui.StepText || next.Wizard().Prompt != "SSH port [2222]:" {
		t.Fatalf("unexpected wizard: %#v", next.Wizard())
	}
	if cmd == nil {
		t.Fatal("expected blink cmd")
	}
}

// TestCreateVPNWizardRejectsSSHPort verifies create wizard rejects SSH listen port.

func TestCreateVPNWizardBackFromPort(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	protocolSnap := tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Step: 1, StepType: tui.StepPicker,
		Prompt: "Select Protocol:", VPNName: "my-vpn",
		Picker: []string{"socks5", "http"}, PickerIdx: 0, Protocol: "socks5",
	}
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "socks5", Step: 2,
		StepType: tui.StepText, Prompt: "Port [1080]:", BasePrompt: "Port [1080]:",
		VPNName: "my-vpn", Input: tui.NewTextInputForTest("1080"),
		WizardHistory: []tui.WizardStateForTest{protocolSnap},
	})
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlP})
	m2 := next
	if m2.Wizard().StepType != tui.StepPicker {
		t.Fatalf("expected picker after back, got %v", m2.Wizard().StepType)
	}
	if m2.Wizard().Prompt != "Select Protocol:" {
		t.Fatalf("expected protocol prompt, got %q", m2.Wizard().Prompt)
	}
}

// TestCreateVPNWizardTextInputAllowsLettersAndArrows verifies text steps do not steal typing keys.

func TestStartWizardAddClient(t *testing.T) {
	m, _ := newTestServiceModel(t)
	m.SetBootstrapped(true)
	m.SetScreen(tui.ScreenClients)
	m.SetItems(tui.ClientMenuItemsForTest())
	m.SetCursor(0)
	next, cmd := m.HandleSelect()
	if next.Mode() != tui.ModeWizard || next.Wizard().Kind != tui.WizardAddClient {
		t.Fatalf("expected add client wizard, got kind=%v", next.Wizard().Kind)
	}
	if cmd == nil {
		t.Fatal("expected load vpns cmd")
	}
}

func TestStartCongestionWizard(t *testing.T) {
	m, _ := newTestServiceModel(t)
	m.SetBootstrapped(true)
	m.SetScreen(tui.ScreenSystem)
	m.SetItems(tui.SystemMenuItemsForTest())
	m.SetCursor(2)
	next, cmd := m.HandleSelect()
	if next.Wizard().Kind != tui.WizardSetCongestion || !next.Wizard().Loading {
		t.Fatal("expected congestion wizard loading")
	}
	if cmd == nil {
		t.Fatal("expected load cmd")
	}
}

func TestStartRestoreBackupWizard(t *testing.T) {
	m, _ := newTestServiceModel(t)
	next, cmd := m.StartRestoreBackupWizard()
	if next.Wizard().Kind != tui.WizardRestoreBackup || !next.Wizard().Loading {
		t.Fatal("expected restore backup wizard")
	}
	if cmd == nil {
		t.Fatal("expected load backups cmd")
	}
}

func TestCancelWizard(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN})
	next, cmd := m.CancelWizard()
	if next.Mode() != tui.ModeMenu || cmd != nil {
		t.Fatal("expected menu mode after cancel")
	}
}

func TestWizardCreateVPNBack(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind:          tui.WizardCreateVPN,
		WizardHistory: []tui.WizardStateForTest{{Kind: tui.WizardCreateVPN, Prompt: "VPN name:"}},
	})
	next, _ := m.WizardCreateVPNBack()
	if next.Wizard().Prompt != "VPN name:" {
		t.Fatalf("expected restored prompt, got %q", next.Wizard().Prompt)
	}
}
