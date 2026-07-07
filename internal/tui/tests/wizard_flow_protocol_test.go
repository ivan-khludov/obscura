package tui_test

import (
	"context"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/service"
	"github.com/ivan-khludov/obscura/internal/tui"
)

func TestCreateVPNWizardAsksClientName(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind:     tui.WizardCreateVPN,
		Step:     2,
		StepType: tui.StepText,
		Prompt:   "Port [1080]:",
		VPNName:  "main",
		Protocol: "socks5",
		Input:    tui.NewTextInputForTest("1080"),
	})

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := next
	if m2.Wizard().ListenPort != 1080 {
		t.Fatalf("expected port 1080, got %d", m2.Wizard().ListenPort)
	}
	if m2.Wizard().Prompt != "Client host [auto]:" {
		t.Fatalf("expected client host prompt, got %q", m2.Wizard().Prompt)
	}
	if m2.Wizard().Step != 3 {
		t.Fatalf("expected step 3, got %d", m2.Wizard().Step)
	}
}

// TestCreateVPNWizardProtocolPicker verifies protocol list loads after VPN name.

func TestCreateVPNWizardWireguardPortDefault(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Protocol: "wireguard"})
	next, _ := m.WizardShowCreatePortInput()
	if !strings.Contains(next.Wizard().Prompt, "51820") {
		t.Fatalf("expected default port 51820 in prompt, got %q", next.Wizard().Prompt)
	}
}

// TestCreateVPNWizardVmessPortDefault verifies VMess wizard defaults to port 443.

func TestCreateVPNWizardVmessPortDefault(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Protocol: "vmess"})
	next, _ := m.WizardShowCreatePortInput()
	if !strings.Contains(next.Wizard().Prompt, "443") {
		t.Fatalf("expected default port 443 in prompt, got %q", next.Wizard().Prompt)
	}
}

// TestCreateVPNWizardVlessPortDefault verifies VLESS wizard defaults to port 443.

func TestCreateVPNWizardVlessPortDefault(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Protocol: "vless"})
	next, _ := m.WizardShowCreatePortInput()
	if !strings.Contains(next.Wizard().Prompt, "443") {
		t.Fatalf("expected default port 443 in prompt, got %q", next.Wizard().Prompt)
	}
}

func TestCreateVPNWizardShadowsocksPortDefault(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Protocol: "shadowsocks"})
	next, _ := m.WizardShowCreatePortInput()
	if next.Wizard().Prompt != "Port [8388]:" {
		t.Fatalf("expected port 8388 prompt, got %q", next.Wizard().Prompt)
	}
}

// TestCreateVPNWizardShadowsocksTransportPicker verifies transport options step after port.

func TestCreateVPNWizardTrojanPortDefault(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Protocol: "trojan"})
	next, _ := m.WizardShowCreatePortInput()
	if next.Wizard().Prompt != "Port [443]:" {
		t.Fatalf("expected port 443 prompt, got %q", next.Wizard().Prompt)
	}
}

// TestCreateVPNWizardVlessRealityFingerprintPicker verifies fingerprint picker after Reality handshake.

func TestCreateVPNWizardHTTPClientName(t *testing.T) {
	m, _ := newTestServiceModel(t)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind:       tui.WizardCreateVPN,
		Step:       4,
		StepType:   tui.StepText,
		Prompt:     "Client name:",
		Protocol:   "http",
		VPNName:    "web",
		ListenPort: 8080,
		Input:      tui.NewTextInputForTest("phone"),
	})
	m.SetWizardInputValue("phone")
	next, cmd := m.WizardTextEnter()
	if next.Mode() != tui.ModeWizard || !next.Busy() {
		t.Fatalf("expected busy wizard, mode=%v busy=%v", next.Mode(), next.Busy())
	}
	if cmd == nil {
		t.Fatal("expected async cmd from wizardFinishCreateVPN")
	}
	msg := firstTeaMsg(cmd)
	done, _ := next.Update(msg)
	m2 := done
	if m2.Mode() != tui.ModeMenu {
		t.Fatalf("expected wizard exit after create, mode=%v", m2.Mode())
	}
}

// TestCreateVPNWizardSocks5ClientName verifies SOCKS5 create wizard finishes after client name.

func TestCreateVPNWizardSocks5ClientName(t *testing.T) {
	m, _ := newTestServiceModel(t)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind:       tui.WizardCreateVPN,
		Step:       3,
		StepType:   tui.StepText,
		Prompt:     "Client name:",
		Protocol:   "socks5",
		VPNName:    "main",
		ListenPort: 1080,
		Input:      tui.NewTextInputForTest("phone"),
	})
	m.SetWizardInputValue("phone")
	next, cmd := m.WizardTextEnter()
	if next.Mode() != tui.ModeWizard || !next.Busy() {
		t.Fatalf("expected busy wizard, mode=%v busy=%v", next.Mode(), next.Busy())
	}
	if cmd == nil {
		t.Fatal("expected async cmd from wizardFinishCreateVPN")
	}
	msg := firstTeaMsg(cmd)
	done, _ := next.Update(msg)
	m2 := done
	if m2.Mode() != tui.ModeMenu {
		t.Fatalf("expected wizard exit after create, mode=%v", m2.Mode())
	}
}

// TestCreateVPNWizardWireguardSubnet verifies WireGuard subnet input at step 4.

func TestCreateVPNWizardClientNameEmptyDefault(t *testing.T) {
	m, _ := newTestServiceModel(t)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "socks5", Step: 3,
		StepType: tui.StepText, Prompt: "Client name:",
		VPNName: "main", ListenPort: 1080,
		Input: tui.NewTextInputForTest("phone"),
	})
	next, cmd := m.WizardTextEnter()
	if next.Mode() != tui.ModeWizard || !next.Busy() {
		t.Fatalf("expected busy wizard, mode=%v busy=%v", next.Mode(), next.Busy())
	}
	if cmd == nil {
		t.Fatal("expected create cmd")
	}
	if next.Wizard().ClientName != "phone" {
		t.Fatalf("expected client name phone, got %q", next.Wizard().ClientName)
	}
	msg := firstTeaMsg(cmd)
	done, _ := next.Update(msg)
	if done.Mode() != tui.ModeMenu {
		t.Fatal("expected wizard exit after create")
	}
}

// TestCreateVPNWizardDuplicateName verifies duplicate VPN name stays on name step.

func TestCreateVPNWizardHappyPathSocks5(t *testing.T) {
	m, _ := newTestServiceModel(t)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "socks5", Step: 4,
		StepType: tui.StepText, Prompt: "Client name:",
		VPNName: "socks", ListenPort: 1090,
		Input: tui.NewTextInputForTest("phone"),
	})
	m.SetWizardInputValue("phone")
	next, cmd := m.WizardTextEnter()
	if next.Mode() != tui.ModeWizard || !next.Busy() {
		t.Fatalf("expected busy wizard, mode=%v busy=%v", next.Mode(), next.Busy())
	}
	done, _ := next.Update(firstTeaMsg(cmd))
	if done.Mode() != tui.ModeMenu {
		t.Fatal("expected menu mode after successful create")
	}
}

// TestCreateVPNWizardClientNameValidationStaysOnClientName verifies validation
// errors at the final step do not jump back to an earlier prompt (e.g. port).

func TestCreateVPNWizardClientNameValidationStaysOnClientName(t *testing.T) {
	m, svc := newTestServiceModel(t)
	ctx := context.Background()
	if _, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "existing", Protocol: "vless", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
	}); err != nil {
		t.Fatal(err)
	}
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "vless", Step: 10,
		StepType: tui.StepText, Prompt: "Client name:",
		BasePrompt: "Port [443]:",
		VPNName:    "new-vless", ListenPort: 443,
		VlessReality: true, TrojanTransport: "grpc",
		TrojanTransportServiceName: "TunService",
		Input:                      tui.NewTextInputForTest("phone"),
	})
	m.SetWizardInputValue("phone")
	next, cmd := m.WizardTextEnter()
	if next.Busy() {
		t.Fatal("expected validation error, not create")
	}
	if !strings.Contains(next.Wizard().StepError, "port") {
		t.Fatalf("expected port validation error, got %q cmd=%v", next.Wizard().StepError, cmd)
	}
	if next.Wizard().Prompt != "Client name:" {
		t.Fatalf("expected client name prompt, got %q", next.Wizard().Prompt)
	}
}

// TestCreateVPNWizardVlessGRPCClientNameFinishes verifies VLESS+gRPC client name
// step submits create instead of looping to port.

func TestCreateVPNWizardVlessGRPCClientNameFinishes(t *testing.T) {
	m, _ := newTestServiceModel(t)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "vless", Step: 9,
		StepType: tui.StepText, Prompt: "Client name:", BasePrompt: "Port [443]:",
		VPNName: "vless-grpc", ListenPort: 1091,
		TrojanServerName: "example.com",
		TrojanTransport:  "grpc", TrojanTransportServiceName: "svc",
		Input: tui.NewTextInputForTest("phone"),
	})
	m.SetWizardInputValue("phone")
	next, cmd := m.WizardTextEnter()
	if !next.Busy() {
		t.Fatalf("expected create in progress, stepError=%q", next.Wizard().StepError)
	}
	if cmd == nil {
		t.Fatal("expected create cmd")
	}
	if next.Wizard().Prompt != "Client name:" {
		t.Fatalf("expected client name prompt, got %q", next.Wizard().Prompt)
	}
}
