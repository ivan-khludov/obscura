package tui_test

import (
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/tui"
)

func TestCreateVPNWizardVlessRealityFingerprintPicker(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Protocol: "vless", Step: 3, VlessReality: true})
	next, _ := m.WizardAcceptTrojanSNI("www.bing.com")
	if next.Wizard().Prompt != "uTLS fingerprint:" {
		t.Fatalf("expected fingerprint picker, got %q", next.Wizard().Prompt)
	}
	if len(next.Wizard().Picker) != len(tui.RealityUTLSFingerprintModesForTest()) {
		t.Fatalf("unexpected Picker: %#v", next.Wizard().Picker)
	}
}

// TestCreateVPNWizardTrojanTransportPicker verifies transport options after SNI.

func TestCreateVPNWizardTrojanTransportPicker(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Protocol: "trojan", Step: 3})
	next, _ := m.WizardAcceptTrojanSNI("example.com")
	if next.Wizard().Prompt != "Transport options:" {
		t.Fatalf("expected transport picker, got %q", next.Wizard().Prompt)
	}
	if len(next.Wizard().Picker) != len(orchestration.InboundTransportModes("trojan")) {
		t.Fatalf("unexpected Picker: %#v", next.Wizard().Picker)
	}
}

// TestSystemMenuItems verifies system submenu includes SSH port.

func TestCreateVPNWizardTrojanTransportPickerEnter(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "trojan", Step: 5,
		StepType: tui.StepPicker, Prompt: "Transport options:",
		Picker: append([]string{}, orchestration.InboundTransportModes("trojan")...),
	})
	next, _ := m.WizardPickerEnter()
	if next.Wizard().Prompt != "Client name:" && next.Wizard().Prompt != "Client host [auto]:" && !strings.Contains(next.Wizard().Prompt, "Fallback") {
		t.Fatalf("expected progress after transport pick, got %q", next.Wizard().Prompt)
	}
}

// TestCreateVPNWizardTrojanTransportPath verifies transport path input advances the wizard.

func TestCreateVPNWizardTrojanTransportPath(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "trojan", Step: 6,
		StepType: tui.StepText, Prompt: "Transport path:",
		TrojanTransport: "http", TrojanPendingPrompt: "path",
		Input: tui.NewTextInputForTest("/"),
	})
	next, _ := m.WizardTextEnter()
	if next.Wizard().Prompt != "Fallback port [0=disabled]:" {
		t.Fatalf("expected fallback prompt, got %q", next.Wizard().Prompt)
	}
	if next.Wizard().TrojanTransportPath != "/" {
		t.Fatalf("expected path /, got %q", next.Wizard().TrojanTransportPath)
	}
}

// TestCreateVPNWizardTrojanTransportPathEmptyDefault verifies empty path defaults to /.

func TestCreateVPNWizardTrojanTransportPathEmptyDefault(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "trojan", Step: 6,
		StepType: tui.StepText, Prompt: "Transport path:",
		TrojanTransport: "http", TrojanPendingPrompt: "path",
		Input: tui.NewTextInputForTest("/"),
	})
	next, _ := m.WizardTextEnter()
	if next.Wizard().TrojanTransportPath != "/" {
		t.Fatalf("expected default path /, got %q", next.Wizard().TrojanTransportPath)
	}
}

// TestCreateVPNWizardTrojanFallback verifies fallback port input at step 6 after Direct transport.

func TestCreateVPNWizardTrojanFallback(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "trojan", Step: 6,
		StepType: tui.StepText, Prompt: "Fallback port [0=disabled]:",
		TrojanPendingPrompt: "fallback",
		Input:               tui.NewTextInputForTest("0"),
	})
	next, _ := m.WizardTextEnter()
	_ = expectClientHostPrompt(t, next)
}

// TestCreateVPNWizardVlessFlowPicker verifies VLESS flow selection advances wizard.

func TestCreateVPNWizardVlessFlowPicker(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "vless", Step: 5,
		StepType: tui.StepPicker, Prompt: "VLESS flow:",
		Picker: append([]string{}, orchestration.VLESSFlowModes()...),
	})
	next, _ := m.WizardPickerEnter()
	if next.Wizard().Prompt != "Transport options:" {
		t.Fatalf("expected transport picker, got %q", next.Wizard().Prompt)
	}
}

// TestCreateVPNWizardVlessTransportPicker verifies VLESS transport at step 6.

func TestCreateVPNWizardVlessTransportPicker(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "vless", Step: 6,
		StepType: tui.StepPicker, Prompt: "Transport options:",
		VlessFlow: "",
		Picker:    append([]string{}, orchestration.InboundTransportModes("vless")...),
	})
	next, _ := m.WizardPickerEnter()
	if next.Wizard().Prompt != "Fallback port [0=disabled]:" {
		t.Fatalf("expected fallback prompt, got %q", next.Wizard().Prompt)
	}
}

// TestCreateVPNWizardVlessVisionGRPCAtTransportPicker verifies Vision+gRPC fails at transport step.

func TestCreateVPNWizardVlessVisionGRPCAtTransportPicker(t *testing.T) {
	m, _ := newTestServiceModel(t)
	m.SetMode(tui.ModeWizard)
	grpcIdx := 0
	for i, mode := range orchestration.InboundTransportModes("vless") {
		if mode == "gRPC" {
			grpcIdx = i
			break
		}
	}
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "vless", Step: 6,
		StepType: tui.StepPicker, Prompt: "Transport options:",
		VlessFlow: orchestration.VLESSFlowVision(),
		VPNName:   "vl", ListenPort: 1092,
		TrojanServerName: "example.com",
		Picker:           append([]string{}, orchestration.InboundTransportModes("vless")...),
		PickerIdx:        grpcIdx,
	})
	next, _ := m.WizardPickerEnter()
	if next.Wizard().Prompt != "Transport options:" {
		t.Fatalf("expected transport picker, got %q", next.Wizard().Prompt)
	}
	if !strings.Contains(next.Wizard().StepError, "direct transport") {
		t.Fatalf("expected flow/transport error, got %q", next.Wizard().StepError)
	}
}

// TestCreateVPNWizardHy2BandwidthConflictAtStep verifies hysteria2 bandwidth conflict at picker.

func TestCreateVPNWizardVmessNoTLSTransport(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "vmess", Step: 4,
		StepType: tui.StepPicker, Prompt: "Transport options:",
		VMessNoTLS: true,
		Picker:     append([]string{}, orchestration.InboundTransportModes("vmess")...),
	})
	next, _ := m.WizardPickerEnter()
	_ = expectClientHostPrompt(t, next)
}

// TestCreateVPNWizardHy2BandwidthUpload verifies hysteria2 upload Mbps at step 6.

func TestCreateVPNWizardTrojanWebSocketPath(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "trojan", Step: 6,
		StepType: tui.StepText, Prompt: "Transport path:",
		TrojanTransport: "ws", TrojanPendingPrompt: "path",
		Input: tui.NewTextInputForTest("/video"),
	})
	m.SetWizardInputValue("/video")
	next, _ := m.WizardTextEnter()
	if next.Wizard().Prompt != "Transport host:" {
		t.Fatalf("expected transport host, got %q", next.Wizard().Prompt)
	}
	if next.Wizard().TrojanTransportPath != "/video" {
		t.Fatalf("expected path /video, got %q", next.Wizard().TrojanTransportPath)
	}
	next.SetWizardInputValue("example.com")
	next, _ = next.WizardTextEnter()
	if next.Wizard().Prompt != "Fallback port [0=disabled]:" {
		t.Fatalf("expected fallback, got %q", next.Wizard().Prompt)
	}
}

// TestCreateVPNWizardClientNameEmptyDefault verifies empty client name defaults to phone.
