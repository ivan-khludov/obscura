package tui_test

import (
	"github.com/ivan-khludov/obscura/internal/tui"
	"strings"
	"testing"
)

func TestCreateVPNWizardHy2BandwidthConflictAtStep(t *testing.T) {
	m, _ := newTestServiceModel(t)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "hysteria2", Step: 5,
		StepType: tui.StepPicker, Prompt: "Bandwidth:",
		VPNName: "hy", ListenPort: 1093,
		Hy2ServerName: "example.com",
		Hy2UpMbps:     100,
		Hy2DownMbps:   100,
		Picker:        []string{"No limit", "Set bandwidth", "Ignore client bandwidth (BBR)"},
		PickerIdx:     2,
	})
	next, _ := m.WizardPickerEnter()
	if next.Wizard().Prompt != "Bandwidth:" {
		t.Fatalf("expected bandwidth picker, got %q", next.Wizard().Prompt)
	}
	if !strings.Contains(next.Wizard().StepError, "ignore_client_bandwidth") {
		t.Fatalf("expected bandwidth conflict error, got %q", next.Wizard().StepError)
	}
}

// TestCreateVPNWizardVmessNoTLSTransport verifies VMess without TLS transport picker.

func TestCreateVPNWizardHy2BandwidthUpload(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "hysteria2", Step: 6,
		StepType: tui.StepText, Prompt: "Upload bandwidth (Mbps) [100]:",
		Hy2PendingPrompt: "up_mbps",
		Input:            tui.NewTextInputForTest("100"),
	})
	next, _ := m.WizardTextEnter()
	if next.Wizard().Hy2PendingPrompt != "down_mbps" {
		t.Fatalf("expected down_mbps prompt, got %q", next.Wizard().Hy2PendingPrompt)
	}
	if !strings.HasPrefix(next.Wizard().Prompt, "Download bandwidth") {
		t.Fatalf("expected download prompt, got %q", next.Wizard().Prompt)
	}
}

// TestCreateVPNWizardHy2BandwidthDown verifies hysteria2 download Mbps advances to obfs.

func TestCreateVPNWizardHy2BandwidthDown(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "hysteria2", Step: 6,
		StepType: tui.StepText, Prompt: "Download bandwidth (Mbps) [100]:",
		Hy2PendingPrompt: "down_mbps", Hy2UpMbps: 100,
		Input: tui.NewTextInputForTest("100"),
	})
	next, _ := m.WizardTextEnter()
	if next.Wizard().Prompt != "Obfuscation:" {
		t.Fatalf("expected obfs picker, got %q", next.Wizard().Prompt)
	}
}

// TestCreateVPNWizardHy2MasqueradeProxy verifies hysteria2 masquerade URL input.

func TestCreateVPNWizardHy2MasqueradeProxy(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "hysteria2", Step: 8,
		StepType: tui.StepText, Prompt: "Masquerade proxy URL [http://127.0.0.1:8080]:",
		Hy2PendingPrompt: "masquerade_proxy",
		Input:            tui.NewTextInputForTest("http://127.0.0.1:8080"),
	})
	next, _ := m.WizardTextEnter()
	_ = expectClientHostPrompt(t, next)
}

// TestCreateVPNWizardHy2ShortPath verifies hysteria2 no-limit path through pickers.

func TestCreateVPNWizardHy2ShortPath(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "hysteria2", Step: 5,
		StepType: tui.StepPicker, Prompt: "Bandwidth:",
		Picker: []string{"No limit", "Set bandwidth", "Ignore client bandwidth (BBR)"},
	})
	next, _ := m.WizardPickerEnter()
	if next.Wizard().Prompt != "Obfuscation:" {
		t.Fatalf("expected obfs after no limit, got %q", next.Wizard().Prompt)
	}
	next.SetWizardPickerIdx(0)
	next, _ = next.WizardPickerEnter()
	if next.Wizard().Prompt != "Masquerade:" {
		t.Fatalf("expected masquerade picker, got %q", next.Wizard().Prompt)
	}
	next.SetWizardPickerIdx(0)
	next, _ = next.WizardPickerEnter()
	_ = expectClientHostPrompt(t, next)
}

// TestCreateVPNWizardTuicPath verifies tuic picker chain.
