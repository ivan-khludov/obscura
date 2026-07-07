package tui_test

import (
	"github.com/ivan-khludov/obscura/internal/tui"
	"testing"
)

func TestCreateVPNWizardTuicPath(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "tuic", Step: 5,
		StepType: tui.StepPicker, Prompt: "Congestion control:",
		Picker: []string{"Cubic", "New Reno", "BBR"},
	})
	next, _ := m.WizardPickerEnter()
	if next.Wizard().Prompt != "0-RTT handshake:" {
		t.Fatalf("expected 0-RTT picker, got %q", next.Wizard().Prompt)
	}
	next.SetWizardPickerIdx(0)
	next, _ = next.WizardPickerEnter()
	_ = expectClientHostPrompt(t, next)
}

// TestCreateVPNWizardTrojanWebSocketPath verifies trojan WS transport path and host.
