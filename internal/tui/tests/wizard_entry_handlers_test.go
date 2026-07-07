package tui_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/service"
	"github.com/ivan-khludov/obscura/internal/tui"
)

func TestCreateVPNEmptyNameIgnored(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind:     tui.WizardCreateVPN,
		Step:     0,
		StepType: tui.StepText,
		Prompt:   "VPN name:",
		Input:    tui.NewTextInputForTest(""),
	})

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := next
	if m2.Busy() {
		t.Fatal("empty name must not start async action")
	}
	if cmd != nil {
		t.Fatal("expected no cmd for empty name")
	}
}

// TestWizardTextInputAcceptsNavigationKeys verifies q/j/k are typed, not menu shortcuts.

func TestCreateVPNWizardDuplicateName(t *testing.T) {
	m, svc := newTestServiceModel(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080},
	}); err != nil {
		t.Fatal(err)
	}
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Step: 0, StepType: tui.StepText,
		Prompt: "VPN name:", BasePrompt: "VPN name:",
		Input: tui.NewTextInputForTest("main"),
	})
	m.SetWizardInputValue("main")
	next, cmd := m.WizardTextEnter()
	if next.Mode() != tui.ModeWizard {
		t.Fatalf("expected wizard mode, got %v", next.Mode())
	}
	if !strings.Contains(next.Wizard().StepError, "already exists") {
		t.Fatalf("expected duplicate error, got %q cmd=%v", next.Wizard().StepError, cmd)
	}
}

// TestCreateVPNWizardDuplicatePort verifies duplicate listen port stays on port step.

func TestCreateVPNWizardDuplicatePort(t *testing.T) {
	m, svc := newTestServiceModel(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080},
	}); err != nil {
		t.Fatal(err)
	}
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "socks5", Step: 2,
		StepType: tui.StepText, Prompt: "Port [1080]:", BasePrompt: "Port [1080]:",
		VPNName: "other", Input: tui.NewTextInputForTest("1080"),
	})
	next, _ := m.WizardTextEnter()
	if next.Mode() != tui.ModeWizard {
		t.Fatalf("expected wizard mode, got %v", next.Mode())
	}
	if next.Wizard().StepError == "" {
		t.Fatal("expected port step error")
	}
	if !strings.HasPrefix(next.Wizard().Prompt, "Port [") {
		t.Fatalf("expected port prompt, got %q", next.Wizard().Prompt)
	}
}

// TestCreateVPNWizardCreateErrorRecovery verifies CreateVPN failure keeps wizard on client name.

func TestCreateVPNWizardCreateErrorRecovery(t *testing.T) {
	m, _ := newTestServiceModel(t)
	m.SetMode(tui.ModeWizard)
	m.SetBusy(true)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "socks5",
		StepType: tui.StepText, Prompt: "Client name:", BasePrompt: "Client name:",
		VPNName: "main", ListenPort: 1090, ClientName: "phone",
		Input: tui.NewTextInputForTest("phone"),
	})
	next, _ := m.Update(tui.NewCreateVPNResultMsgForTest("", errors.New("apply configuration: boom")))
	m2 := next
	if m2.Mode() != tui.ModeWizard {
		t.Fatalf("expected wizard mode, got %v", m2.Mode())
	}
	if m2.Busy() {
		t.Fatal("expected busy cleared")
	}
	if !strings.Contains(m2.Wizard().StepError, "boom") {
		t.Fatalf("expected error message, got %q", m2.Wizard().StepError)
	}
	if m2.Wizard().Prompt != "Client name:" {
		t.Fatalf("expected client name prompt, got %q", m2.Wizard().Prompt)
	}
}

// TestCreateVPNWizardBackFromPort verifies ctrl+p returns to protocol picker from port step.
