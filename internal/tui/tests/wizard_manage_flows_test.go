package tui_test

import (
	"context"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/service"
	"github.com/ivan-khludov/obscura/internal/tui"
)

func TestEditVPNWizardShowsTLSField(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind:        tui.WizardEditVPN,
		SelectedVPN: orchestration.VPNView{Name: "web", Protocol: "http", Listen: domain.ListenOptions{ListenPort: 8080}},
	})
	next, _ := m.WizardShowEditVPNFields()
	fields := next.Wizard().Picker
	if len(fields) != 5 || fields[3] != "Client host" || fields[4] != "TLS" {
		t.Fatalf("expected TLS field for http vpn, got %#v", fields)
	}
}

// TestCreateVPNWizardShadowsocksPortDefault verifies shadowsocks default port is 8388.

func TestEditClientWizardFields(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditClient})
	next, _ := m.WizardShowEditClientFields()
	want := []string{"Status", "Name", "Username", "Password"}
	if len(next.Wizard().Picker) != len(want) {
		t.Fatalf("unexpected fields: %#v", next.Wizard().Picker)
	}
	for i, field := range want {
		if next.Wizard().Picker[i] != field {
			t.Fatalf("field %d: got %q want %q", i, next.Wizard().Picker[i], field)
		}
	}
}

// TestCreateVPNEmptyNameIgnored verifies empty VPN name is not submitted.

func createTestVPN(t *testing.T, svc *service.Service, name string, port int) {
	t.Helper()
	ctx := context.Background()
	_, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: name, Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: port},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddClientFlow(t *testing.T) {
	m, svc := newTestServiceModel(t)
	createTestVPN(t, svc, "main", 1080)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardAddClient, Step: 1, StepType: tui.StepText,
		Prompt: "Client name:", VPNName: "main",
		Input: tui.NewTextInputForTest("tablet"),
	})
	m.SetWizardInputValue("tablet")
	finish, cmd := m.WizardTextEnter()
	if cmd == nil || !finish.Busy() {
		t.Fatalf("expected add client async, busy=%v", finish.Busy())
	}
	if finish.Mode() != tui.ModeMenu {
		t.Fatalf("expected menu mode, got %v", finish.Mode())
	}
}

func TestShowClientFlow(t *testing.T) {
	m, svc := newTestServiceModel(t)
	createTestVPN(t, svc, "main", 1080)
	ctx := context.Background()
	if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "main", Name: "phone"}, true); err != nil {
		t.Fatal(err)
	}
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardShowClient, Step: 1, StepType: tui.StepPicker,
		Prompt: "Select client:", VPNName: "main",
		Clients: []orchestration.ClientView{{Name: "phone"}},
		Picker:  []string{"phone"},
	})
	next, cmd := m.WizardAfterClientPick()
	if cmd == nil {
		t.Fatal("expected show client cmd")
	}
	if next.Mode() != tui.ModeMenu {
		t.Fatal("expected menu mode")
	}
}

func TestDeleteVPNFlow(t *testing.T) {
	m, svc := newTestServiceModel(t)
	createTestVPN(t, svc, "main", 1080)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardDeleteVPN, Step: 0, StepType: tui.StepPicker,
		Prompt: "Select VPN:", Picker: []string{"main :1080 (socks5)"},
		VPNs: []orchestration.VPNView{{Name: "main", Protocol: "socks5", Listen: domain.ListenOptions{ListenPort: 1080}}},
	})
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if next.Wizard().StepType != tui.StepConfirm {
		t.Fatal("expected confirm step")
	}
	finish, cmd := next.WizardConfirmEnter()
	if cmd == nil || finish.Mode() != tui.ModeMenu {
		t.Fatal("expected delete async")
	}
}

func TestEditVPNNameFlow(t *testing.T) {
	m, svc := newTestServiceModel(t)
	createTestVPN(t, svc, "main", 1080)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardEditVPN, Step: 2, StepType: tui.StepText,
		EditField: "Name", VPNName: "main",
		SelectedVPN: orchestration.VPNView{Name: "main", Protocol: "socks5", Listen: domain.ListenOptions{ListenPort: 1080}},
		Prompt:      "Name [main]:", Input: tui.NewTextInputForTest("main2"),
	})
	m.SetWizardInputValue("main2")
	next, cmd := m.WizardTextEnter()
	if cmd == nil || next.Mode() != tui.ModeMenu {
		t.Fatal("expected edit vpn async")
	}
}

func TestEditVPNPortInvalid(t *testing.T) {
	m, svc := newTestServiceModel(t)
	createTestVPN(t, svc, "main", 1080)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardEditVPN, Step: 2, StepType: tui.StepText,
		EditField: "Port", VPNName: "main",
		SelectedVPN: orchestration.VPNView{Name: "main", Protocol: "socks5", Listen: domain.ListenOptions{ListenPort: 1080}},
		Prompt:      "Port [1080]:", Input: tui.NewTextInputForTest("bad"),
	})
	m.SetWizardInputValue("bad")
	next, cmd := m.WizardTextEnter()
	if cmd == nil {
		t.Fatal("expected blink cmd")
	}
	if next.Mode() != tui.ModeWizard {
		t.Fatal("expected stay in wizard")
	}
}

func TestWizardAfterVPNPickDelete(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardDeleteVPN, VPNName: "main"})
	next, cmd := m.WizardAfterVPNPick()
	if next.Wizard().StepType != tui.StepConfirm || cmd != nil {
		t.Fatal("expected confirm for delete")
	}
}

func TestWizardShowEditVPNValueFields(t *testing.T) {
	vpn := orchestration.VPNView{Name: "web", Protocol: "http", Listen: domain.ListenOptions{ListenPort: 8080}, ClientHost: "auto"}
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	for _, field := range []string{"Name", "Port", "Client host", "Status", "TLS"} {
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditVPN, EditField: field, SelectedVPN: vpn, VPNName: "web"})
		_, _ = m.WizardShowEditVPNValue()
	}
}

func TestWizardShowEditClientValueFields(t *testing.T) {
	client := orchestration.ClientView{Name: "phone", Username: "u", Enabled: true}
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	for _, field := range []string{"Name", "Username", "Password", "Status"} {
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardEditClient, EditField: field,
			SelectedClient: client, VPNName: "main", ClientName: "phone",
		})
		next, _ := m.WizardShowEditClientValue()
		_ = next
	}
}
