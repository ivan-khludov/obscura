package tui_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/tui"
)

func TestCreateVPNWizardWireguardSubnet(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "wireguard", Step: 4,
		StepType: tui.StepText, ListenPort: 51820,
		Prompt: func() string {
			address, _ := orchestration.WireguardDefaults()
			return fmt.Sprintf("Subnet [%s]:", address)
		}(),
		Input: tui.NewTextInputForTest("10.8.0.1/24"),
	})
	m.SetWizardInputValue("10.8.0.1/24")
	next, _ := m.WizardTextEnter()
	if next.Wizard().Prompt != "WireGuard interface mode:" {
		t.Fatalf("expected interface mode picker, got %q", next.Wizard().Prompt)
	}
	if next.Wizard().Step != 5 {
		t.Fatalf("expected step 5, got %d", next.Wizard().Step)
	}
}

// TestCreateVPNWizardWireguardInterface verifies WireGuard interface picker at step 5.

func TestCreateVPNWizardWireguardInterface(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "wireguard", Step: 5,
		StepType: tui.StepPicker, Prompt: "WireGuard interface mode:",
		Picker: []string{"Direct (userspace)", "System interface"},
	})
	next, _ := m.WizardPickerEnter()
	if !strings.Contains(next.Wizard().Prompt, "MTU") {
		t.Fatalf("expected MTU prompt, got %q", next.Wizard().Prompt)
	}
	if next.Wizard().Step != 6 {
		t.Fatalf("expected step 6, got %d", next.Wizard().Step)
	}
}

// TestCreateVPNWizardTrojanTransportPickerEnter verifies trojan transport selection at step 5.
