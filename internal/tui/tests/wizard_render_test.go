package tui_test

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/tui"
)

func TestViewMainMenu(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetBootstrapped(true)
	m.SetItems(m.MainMenuItems())
	view := m.View()
	if !strings.Contains(view, "obscura") || !strings.Contains(view, "VPNs") {
		t.Fatalf("unexpected view: %q", view)
	}
	if !strings.Contains(view, "ctrl+q quit") {
		t.Fatal("expected main help")
	}
}

func TestViewSubmenuScreen(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetBootstrapped(true)
	next, _ := m.OpenSubmenu(tui.ScreenVPNs, tui.VPNMenuItemsForTest())
	view := next.View()
	if !strings.Contains(view, "obscura / VPNs") {
		t.Fatalf("unexpected title: %q", view)
	}
	if !strings.Contains(view, "ctrl+b back") {
		t.Fatal("expected back help")
	}
}

func TestViewWizardModeFrozenCursor(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetBootstrapped(true)
	m.SetItems(m.MainMenuItems())
	m.SetCursor(2)
	m.SetMode(tui.ModeWizard)
	m.SetFrozenCursor(2)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, StepType: tui.StepText, Prompt: "VPN name:",
		Input: tui.NewTextInputForTest(""),
	})
	view := m.View()
	if !strings.Contains(view, "> System") {
		t.Fatalf("expected frozen cursor on System, got: %q", view)
	}
	if !strings.Contains(view, "ctrl+p back") {
		t.Fatal("expected create wizard help")
	}
}

func TestViewBusySpinner(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetBootstrapped(true)
	m.SetItems(m.MainMenuItems())
	m.SetBusy(true)
	m.SetBusyLabel("Working…")
	panel := m.RenderPanel()
	if !strings.Contains(panel, "Working") {
		t.Fatalf("expected spinner panel, got %q", panel)
	}
	view := m.View()
	if !strings.Contains(view, "ctrl+c abort") {
		t.Fatal("expected busy help")
	}
}

func TestViewMessagePanel(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMessage("hello")
	panel := m.RenderPanel()
	if !strings.Contains(panel, "hello") {
		t.Fatalf("expected message panel, got %q", panel)
	}
	view := m.View()
	if !strings.Contains(view, "esc dismiss message") {
		t.Fatal("expected dismiss help")
	}
}

func TestViewQuittingEmpty(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetQuitting(true)
	if m.View() != "" {
		t.Fatal("quitting view should be empty")
	}
}

func TestRenderWizardConfirmStep(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardDeleteVPN, StepType: tui.StepConfirm,
		Prompt: "Delete VPN \"main\" and all clients?",
	})
	panel := m.RenderPanel()
	if !strings.Contains(panel, "Press Enter to confirm") {
		t.Fatalf("expected confirm panel, got %q", panel)
	}
}

func TestRenderWizardNoticeStep(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardAddClient, StepType: tui.StepNotice, Notice: "No VPNs",
	})
	panel := m.RenderPanel()
	if !strings.Contains(panel, "No VPNs") {
		t.Fatalf("expected notice panel, got %q", panel)
	}
	help := m.View()
	if !strings.Contains(help, "enter/esc cancel") {
		t.Fatal("expected notice help")
	}
}

func TestRenderWizardLoading(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardAddClient, Loading: true})
	if !strings.Contains(m.RenderPanel(), "Loading") {
		t.Fatal("expected loading panel")
	}
}

func TestViewAllScreens(t *testing.T) {
	screens := []struct {
		screen int
		title  string
	}{
		{tui.ScreenClients, "obscura / Clients"},
		{tui.ScreenSystem, "obscura / System"},
		{tui.ScreenBackup, "obscura / Backup"},
	}
	for _, tc := range screens {
		m := tui.NewModelForTest(nil, nil)
		m.SetScreen(tc.screen)
		m.SetItems([]string{"item"})
		if !strings.Contains(m.View(), tc.title) {
			t.Fatalf("screen %d: expected %q in view", tc.screen, tc.title)
		}
	}
}

func TestRenderWizardPickerWithVPN(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardAddClient, StepType: tui.StepPicker, Prompt: "Select VPN:",
		Picker: []string{"main :1080 (socks5)"}, PickerIdx: 0,
		VPNs: []orchestration.VPNView{{Name: "main", Protocol: "socks5", Listen: domain.ListenOptions{ListenPort: 1080}}},
	})
	panel := m.RenderPanel()
	if !strings.Contains(panel, "> main") {
		t.Fatalf("expected picker cursor, got %q", panel)
	}
}

func TestWizardCreatePickerHelp(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, StepType: tui.StepPicker, Prompt: "Select protocol:",
		Picker: []string{"socks5"},
	})
	if !strings.Contains(m.View(), "ctrl+p back") {
		t.Fatal("expected create picker back help")
	}
}

func TestWizardNonCreateTextHelp(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardAddClient, StepType: tui.StepText, Prompt: "Client name:"})
	if !strings.Contains(m.View(), "enter confirm") {
		t.Fatal("expected manage text help")
	}
}

func TestWizardPickerNavigationUpdatesView(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardSetCongestion, StepType: tui.StepPicker,
		Picker: []string{"bbr", "cubic"}, PickerIdx: 0,
	})
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	if next.Wizard().PickerIdx != 1 {
		t.Fatal("expected picker idx 1")
	}
}
