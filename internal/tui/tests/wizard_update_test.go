package tui_test

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/tui"
)

func TestEscCancelsWizard(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetFrozenCursor(0)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, StepType: tui.StepText, Prompt: "VPN name:"})

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m2 := next
	if m2.Mode() != tui.ModeMenu {
		t.Fatal("expected menu mode after esc")
	}
}

// TestWizardVPNPickerAdvance verifies selecting a VPN moves to the next wizard step.

func TestWizardVPNPickerAdvance(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind:      tui.WizardAddClient,
		Step:      0,
		StepType:  tui.StepPicker,
		Prompt:    "Select VPN:",
		PickerIdx: 0,
		VPNs:      []orchestration.VPNView{{Name: "main", Protocol: "socks5", Listen: domain.ListenOptions{ListenPort: 1080}}},
		Picker:    []string{"main :1080 (socks5)"},
	})

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := next
	if m2.Wizard().VPNName != "main" {
		t.Fatalf("expected vpn main, got %q", m2.Wizard().VPNName)
	}
	if m2.Wizard().StepType != tui.StepText {
		t.Fatal("expected text step for client name")
	}
}

// TestCreateVPNWizardAsksClientName verifies create VPN wizard prompts for client after port.

func TestWizardTextInputAcceptsNavigationKeys(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind:     tui.WizardCreateVPN,
		Step:     0,
		StepType: tui.StepText,
		Prompt:   "VPN name:",
		Input:    tui.NewTextInputForTest(""),
	})

	for _, r := range []rune{'q', 'j', 'k'} {
		next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		m = next
	}
	if m.WizardInputValue() != "qjk" {
		t.Fatalf("expected qjk in input, got %q", m.WizardInputValue())
	}
	if m.Mode() != tui.ModeWizard {
		t.Fatal("text keys must not cancel wizard")
	}
}

// TestRemoveClientConfirmRequired verifies remove needs confirm step before busy.

func TestRemoveClientConfirmRequired(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind:      tui.WizardRemoveClient,
		Step:      1,
		StepType:  tui.StepPicker,
		Prompt:    "Select client:",
		PickerIdx: 0,
		VPNName:   "main",
		Clients:   []orchestration.ClientView{{Name: "phone"}},
		Picker:    []string{"phone"},
	})

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := next
	if m2.Busy() {
		t.Fatal("picker enter must not start remove yet")
	}
	if m2.Wizard().StepType != tui.StepConfirm {
		t.Fatal("expected confirm step after client pick")
	}
	if cmd != nil {
		t.Fatal("expected no async cmd before confirm")
	}
}

// TestBootstrapProgressMsgUpdatesPercent verifies bootstrap progress replaces spinner.

func TestCreateVPNWizardTextInputAllowsLettersAndArrows(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "vless", Step: 4,
		StepType: tui.StepText, Prompt: "Reality handshake server [auto]:",
		BasePrompt: "Reality handshake server [auto]:", VlessReality: true,
		Input: tui.NewTextInputForTest(""),
	})
	for _, r := range "www.bing.com" {
		next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		m = next
	}
	if m.WizardInputValue() != "www.bing.com" {
		t.Fatalf("expected full hostname in input, got %q", m.WizardInputValue())
	}
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyLeft})
	m = next
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRight})
	m = next
	if m.Wizard().Prompt != "Reality handshake server [auto]:" {
		t.Fatalf("unexpected prompt after typing: %q", m.Wizard().Prompt)
	}
}

// TestCreateVPNWizardHappyPathSocks5 verifies full create flow exits wizard only on success.
