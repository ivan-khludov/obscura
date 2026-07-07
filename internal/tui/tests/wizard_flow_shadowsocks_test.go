package tui_test

import (
	"testing"

	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/tui"
)

func TestCreateVPNWizardShadowsocksTransportPicker(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Protocol: "shadowsocks", Step: 3, ListenPort: 8388})
	next, _ := m.WizardAcceptCreatePort("8388")
	if next.Wizard().Prompt != "Transport options:" {
		t.Fatalf("expected transport picker, got %q", next.Wizard().Prompt)
	}
	if len(next.Wizard().Picker) != len(orchestration.ShadowsocksTransportModes()) {
		t.Fatalf("unexpected Picker: %#v", next.Wizard().Picker)
	}
}

// TestCreateVPNWizardShadowsocksMultiplexClientName verifies client name submits after multiplex pick.

func TestCreateVPNWizardShadowsocksMultiplexClientName(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "shadowsocks", Step: 4,
		VPNName: "ss", SSMethod: orchestration.DefaultShadowsocksMethod(), ListenPort: 8388,
	})
	next, _ := m.WizardAcceptSSTransport(2) // Multiplex (padding).
	next = expectClientHostPrompt(t, next)
	next.SetWizardInputValue("phone")
	finish, cmd := next.WizardTextEnter()
	if cmd == nil {
		t.Fatal("expected async create command")
	}
	if !finish.Busy() {
		t.Fatal("expected busy state after submitting client name")
	}
}

// TestEditClientWizardFields verifies client edit offers expected fields.
