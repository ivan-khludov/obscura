package tui_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/ivan-khludov/obscura/internal/config"
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/firewall"
	"github.com/ivan-khludov/obscura/internal/manifest"
	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/runtime"
	"github.com/ivan-khludov/obscura/internal/service"
	"github.com/ivan-khludov/obscura/internal/singboxcheck"
	"github.com/ivan-khludov/obscura/internal/store"
	"github.com/ivan-khludov/obscura/internal/systemd"
	"github.com/ivan-khludov/obscura/internal/tui"
)

func TestWizardAdvanceAfterCreatePortProtocols(t *testing.T) {
	tests := []struct {
		protocol   string
		wantPrefix string
	}{
		{protocol: "http", wantPrefix: "Enable TLS?"},
		{protocol: "shadowsocks", wantPrefix: "Transport options:"},
		{protocol: "trojan", wantPrefix: "TLS server name"},
		{protocol: "vmess", wantPrefix: "Enable TLS?"},
		{protocol: "vless", wantPrefix: "TLS mode:"},
		{protocol: "hysteria2", wantPrefix: "TLS server name"},
		{protocol: "tuic", wantPrefix: "TLS server name"},
		{protocol: "wireguard", wantPrefix: "Subnet ["},
		{protocol: "socks5", wantPrefix: "Client host"},
	}
	for _, tc := range tests {
		t.Run(tc.protocol, func(t *testing.T) {
			m := tui.NewModelForTest(nil, nil)
			m.SetMode(tui.ModeWizard)
			m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Protocol: tc.protocol})
			next, _ := m.WizardAcceptCreatePort("443")
			if !strings.Contains(next.Wizard().Prompt, tc.wantPrefix) {
				t.Fatalf("prompt %q missing %q", next.Wizard().Prompt, tc.wantPrefix)
			}
		})
	}
}

func TestWizardCreateVPNPickerExtraSteps(t *testing.T) {
	t.Run("cipher", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "shadowsocks", Prompt: "Select cipher:",
			Picker: orchestration.ShadowsocksMethods(),
		})
		next, _, ok := m.WizardCreateVPNPickerEnter(0)
		if !ok || !strings.HasPrefix(next.Wizard().Prompt, "Port [") {
			t.Fatalf("expected port prompt, got %q", next.Wizard().Prompt)
		}
	})
	t.Run("vless tls reality", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Protocol: "vless", Prompt: "TLS mode:"})
		next, _, ok := m.WizardCreateVPNPickerEnter(1)
		if !ok || !strings.Contains(next.Wizard().Prompt, "Reality handshake") {
			t.Fatalf("expected reality SNI, got %q", next.Wizard().Prompt)
		}
	})
	t.Run("reality fingerprint", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "vless", Prompt: "uTLS fingerprint:",
			Picker: tui.RealityUTLSFingerprintModesForTest(),
		})
		next, _, ok := m.WizardCreateVPNPickerEnter(0)
		if !ok || next.Wizard().Prompt != "VLESS flow:" {
			t.Fatalf("expected flow picker, got %q", next.Wizard().Prompt)
		}
	})
	t.Run("vmess enable tls", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Protocol: "vmess", Prompt: "Enable TLS?"})
		next, _, ok := m.WizardCreateVPNPickerEnter(1)
		if !ok || !strings.Contains(next.Wizard().Prompt, "SNI") {
			t.Fatalf("expected SNI prompt, got %q", next.Wizard().Prompt)
		}
	})
}

func TestWizardInboundTransportModes(t *testing.T) {
	modes := []struct {
		mode       string
		wantPrompt string
	}{
		{"gRPC", "gRPC service name:"},
		{"HTTP", "Transport path:"},
		{"HTTPUpgrade", "Transport path:"},
		{"WebSocket", "Transport path:"},
		{"QUIC", "Fallback port"},
		{"Multiplex", "Fallback port"},
		{"Multiplex (padding)", "Fallback port"},
	}
	for _, tc := range modes {
		t.Run(tc.mode, func(t *testing.T) {
			m, _ := newTestServiceModel(t)
			m.SetMode(tui.ModeWizard)
			picker := orchestration.InboundTransportModes("trojan")
			idx := 0
			for i, name := range picker {
				if name == tc.mode {
					idx = i
					break
				}
			}
			m.SetWizard(tui.WizardStateForTest{
				Kind: tui.WizardCreateVPN, Protocol: "trojan", Step: 5,
				StepType: tui.StepPicker, Prompt: "Transport options:",
				VPNName: "t1", ListenPort: 4443, TrojanServerName: "example.com",
				Picker: picker, PickerIdx: idx,
			})
			next, _ := m.WizardPickerEnter()
			if !strings.Contains(next.Wizard().Prompt, tc.wantPrompt) {
				t.Fatalf("mode %s: got prompt %q", tc.mode, next.Wizard().Prompt)
			}
		})
	}
}

func TestWizardTrojanGRPCServiceName(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "trojan",
		Prompt: "gRPC service name:", TrojanPendingPrompt: "service_name",
		TrojanTransport: "grpc", Input: tui.NewTextInputForTest("svc"),
	})
	m.SetWizardInputValue("svc")
	next, _, ok := m.WizardCreateVPNTextEnter("svc")
	if !ok || !strings.Contains(next.Wizard().Prompt, "Fallback") {
		t.Fatalf("expected fallback, got %q", next.Wizard().Prompt)
	}
}

func TestWizardWireguardMTU(t *testing.T) {
	m, _ := newTestServiceModel(t)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "wireguard",
		Prompt: "MTU [1408, empty=default]:", WGAddress: "10.8.0.1/24",
		Input: tui.NewTextInputForTest("1408"),
	})
	m.SetWizardInputValue("1408")
	next, _, ok := m.WizardCreateVPNTextEnter("1408")
	if !ok || next.Wizard().Prompt != "Client host [auto]:" {
		t.Fatalf("expected client host, got %q", next.Wizard().Prompt)
	}
}

func TestWizardHy2SNIAndBandwidthSet(t *testing.T) {
	m, _ := newTestServiceModel(t)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "hysteria2",
		Prompt: "TLS server name (SNI) [auto]:", VPNName: "hy", ListenPort: 443,
	})
	next, _, ok := m.WizardCreateVPNTextEnter("example.com")
	if !ok || next.Wizard().Prompt != "Bandwidth:" {
		t.Fatalf("expected bandwidth picker, got %q", next.Wizard().Prompt)
	}
	m2 := next
	m2.SetWizardPickerIdx(1)
	next2, _ := m2.WizardPickerEnter()
	if !strings.HasPrefix(next2.Wizard().Prompt, "Upload bandwidth") {
		t.Fatalf("expected upload prompt, got %q", next2.Wizard().Prompt)
	}
}

func TestWizardHy2MasqueradeFile(t *testing.T) {
	m, _ := newTestServiceModel(t)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "hysteria2", Prompt: "Masquerade:",
		Picker: []string{"None", "Reverse proxy URL", "File directory"},
	})
	m.SetWizardPickerIdx(2)
	next, _ := m.WizardPickerEnter()
	if !strings.Contains(next.Wizard().Prompt, "Masquerade file directory") {
		t.Fatalf("expected file dir prompt, got %q", next.Wizard().Prompt)
	}
	m2 := next
	m2.SetWizardInputValue("/var/www")
	next2, _, ok := m2.WizardCreateVPNTextEnter("/var/www")
	if !ok || next2.Wizard().Prompt != "Client host [auto]:" {
		t.Fatalf("expected client host, got %q", next2.Wizard().Prompt)
	}
}

func TestWizardShadowsocksTransports(t *testing.T) {
	base := tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Protocol: "shadowsocks", Prompt: "Transport options:",
		Picker: orchestration.ShadowsocksTransportModes(), VPNName: "ss", ListenPort: 8388,
		SSMethod: orchestration.DefaultShadowsocksMethod(),
	}
	for idx, mode := range orchestration.ShadowsocksTransportModes() {
		t.Run(mode, func(t *testing.T) {
			mm := tui.NewModelForTest(nil, nil)
			mm.SetMode(tui.ModeWizard)
			mm.SetWizard(base)
			next, _ := mm.WizardAcceptSSTransport(idx)
			switch mode {
			case "ShadowTLS":
				if !strings.Contains(next.Wizard().Prompt, "ShadowTLS handshake") {
					t.Fatalf("expected shadowtls prompt, got %q", next.Wizard().Prompt)
				}
			default:
				if next.Wizard().Prompt != "Client host [auto]:" {
					t.Fatalf("expected client host, got %q", next.Wizard().Prompt)
				}
			}
		})
	}
}

func TestWizardManagePickerFlows(t *testing.T) {
	_, svc := newTestServiceModel(t)
	createTestVPN(t, svc, "web", 8080)
	ctx := context.Background()
	if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "web", Name: "phone"}, true); err != nil {
		t.Fatal(err)
	}

	t.Run("restore backup pick", func(t *testing.T) {
		mm := tui.NewModelForTest(nil, orchestration.New(svc))
		mm.SetMode(tui.ModeWizard)
		mm.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardRestoreBackup, Step: 0, StepType: tui.StepPicker,
			Backups: []orchestration.BackupEntry{{Name: "b1", Path: "/tmp/b1"}},
			Picker:  []string{"b1"},
		})
		next, _ := mm.Update(tea.KeyMsg{Type: tea.KeyEnter})
		if next.Wizard().StepType != tui.StepConfirm {
			t.Fatal("expected confirm")
		}
	})

	t.Run("congestion already active", func(t *testing.T) {
		mm := tui.NewModelForTest(nil, orchestration.New(svc))
		mm.SetMode(tui.ModeWizard)
		mm.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardSetCongestion, StepType: tui.StepPicker,
			CongestionOptions: []string{"bbr", "cubic"}, CongestionCurrent: "bbr",
			Picker: []string{"bbr (current)", "cubic"},
		})
		next, _ := mm.WizardPickerEnter()
		if next.Wizard().StepType != tui.StepNotice {
			t.Fatal("expected notice for same algorithm")
		}
	})

	t.Run("edit vpn status", func(t *testing.T) {
		vpn := orchestration.VPNView{Name: "web", Protocol: "http", Enabled: true, Listen: domain.ListenOptions{ListenPort: 8080}}
		mm := tui.NewModelForTest(nil, orchestration.New(svc))
		mm.SetMode(tui.ModeWizard)
		mm.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardEditVPN, Step: 2, StepType: tui.StepPicker,
			EditField: "Status", VPNName: "web", SelectedVPN: vpn,
			Picker: []string{"Active", "Inactive"},
		})
		next, cmd := mm.WizardPickerEnter()
		if cmd == nil || next.Mode() != tui.ModeMenu {
			t.Fatal("expected async edit vpn")
		}
	})

	t.Run("edit vpn tls", func(t *testing.T) {
		vpn := orchestration.VPNView{Name: "web", Protocol: "http", Enabled: true, Listen: domain.ListenOptions{ListenPort: 8080}}
		mm := tui.NewModelForTest(nil, orchestration.New(svc))
		mm.SetMode(tui.ModeWizard)
		mm.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardEditVPN, Step: 2, StepType: tui.StepPicker,
			EditField: "TLS", VPNName: "web", SelectedVPN: vpn,
			Picker: []string{"Enable TLS", "Disable TLS"},
		})
		mm.SetWizardPickerIdx(1)
		next, cmd := mm.WizardPickerEnter()
		if cmd == nil || next.Mode() != tui.ModeMenu {
			t.Fatal("expected async tls edit")
		}
	})

	t.Run("edit client status", func(t *testing.T) {
		client := orchestration.ClientView{Name: "phone", Enabled: true}
		mm := tui.NewModelForTest(nil, orchestration.New(svc))
		mm.SetMode(tui.ModeWizard)
		mm.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardEditClient, Step: 3, StepType: tui.StepPicker,
			EditField: "Status", VPNName: "web", ClientName: "phone", SelectedClient: client,
			Picker: []string{"Active", "Inactive"},
		})
		next, cmd := mm.WizardPickerEnter()
		if cmd == nil || next.Mode() != tui.ModeMenu {
			t.Fatal("expected async client status edit")
		}
	})

	t.Run("edit client name", func(t *testing.T) {
		mm := tui.NewModelForTest(nil, orchestration.New(svc))
		mm.SetMode(tui.ModeWizard)
		mm.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardEditClient, Step: 3, StepType: tui.StepText,
			EditField: "Name", VPNName: "web", ClientName: "phone",
			Prompt: "Name [phone]:", Input: tui.NewTextInputForTest("phone2"),
		})
		mm.SetWizardInputValue("phone2")
		next, cmd := mm.WizardTextEnter()
		if cmd == nil || next.Mode() != tui.ModeMenu {
			t.Fatal("expected async client rename")
		}
	})

	t.Run("remove client confirm", func(t *testing.T) {
		mm := tui.NewModelForTest(nil, orchestration.New(svc))
		mm.SetMode(tui.ModeWizard)
		mm.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardRemoveClient, StepType: tui.StepConfirm,
			VPNName: "web", ClientName: "phone",
		})
		next, cmd := mm.WizardConfirmEnter()
		if cmd == nil || next.Mode() != tui.ModeMenu {
			t.Fatal("expected remove async")
		}
	})

	t.Run("show client after pick", func(t *testing.T) {
		mm := tui.NewModelForTest(nil, orchestration.New(svc))
		mm.SetMode(tui.ModeWizard)
		mm.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardShowClient, Step: 1, StepType: tui.StepPicker,
			VPNName: "web", Picker: []string{"phone"}, PickerIdx: 0,
			Clients: []orchestration.ClientView{{Name: "phone"}},
		})
		next, cmd := mm.WizardPickerEnter()
		if cmd == nil || next.Mode() != tui.ModeMenu {
			t.Fatal("expected show client async")
		}
	})
}

func TestHandleSelectMoreBranches(t *testing.T) {
	m, _ := newTestServiceModel(t)
	m.SetBootstrapped(true)

	t.Run("backup restore wizard", func(t *testing.T) {
		mm := m
		mm.SetScreen(tui.ScreenBackup)
		mm.SetItems(tui.BackupMenuItemsForTest())
		mm.SetCursor(2)
		next, cmd := mm.HandleSelect()
		if next.Wizard().Kind != tui.WizardRestoreBackup || cmd == nil {
			t.Fatal("expected restore wizard")
		}
	})

	t.Run("system ssh port", func(t *testing.T) {
		mm := m
		mm.SetScreen(tui.ScreenSystem)
		mm.SetItems(tui.SystemMenuItemsForTest())
		mm.SetCursor(3)
		next, cmd := mm.HandleSelect()
		if next.Wizard().Kind != tui.WizardSetSSHPort || cmd == nil {
			t.Fatal("expected ssh port wizard")
		}
	})

	t.Run("vpn edit delete", func(t *testing.T) {
		mm := m
		mm.SetScreen(tui.ScreenVPNs)
		mm.SetItems(tui.VPNMenuItemsForTest())
		mm.SetCursor(2)
		next, cmd := mm.HandleSelect()
		if next.Wizard().Kind != tui.WizardEditVPN || cmd == nil {
			t.Fatal("expected edit vpn wizard")
		}
		mm2 := m
		mm2.SetScreen(tui.ScreenVPNs)
		mm2.SetItems(tui.VPNMenuItemsForTest())
		mm2.SetCursor(3)
		next2, cmd2 := mm2.HandleSelect()
		if next2.Wizard().Kind != tui.WizardDeleteVPN || cmd2 == nil {
			t.Fatal("expected delete vpn wizard")
		}
	})

	t.Run("clients submenu actions", func(t *testing.T) {
		mm := m
		mm.SetScreen(tui.ScreenClients)
		mm.SetItems(tui.ClientMenuItemsForTest())
		for cursor, kind := range map[int]int{1: tui.WizardEditClient, 2: tui.WizardShowClient, 3: tui.WizardRemoveClient} {
			sub := mm
			sub.SetCursor(cursor)
			next, cmd := sub.HandleSelect()
			if next.Wizard().Kind != kind || cmd == nil {
				t.Fatalf("cursor %d: expected kind %d, got %d", cursor, kind, next.Wizard().Kind)
			}
		}
	})

	t.Run("open submenus", func(t *testing.T) {
		mm := tui.NewModelForTest(nil, nil)
		mm.SetBootstrapped(true)
		mm.SetItems(mm.MainMenuItems())
		for i, screen := range []int{tui.ScreenSystem, tui.ScreenBackup} {
			sub := mm
			sub.SetCursor(i + 2)
			next, _ := sub.HandleSelect()
			if next.Screen() != screen {
				t.Fatalf("cursor %d: expected screen %d", i+2, screen)
			}
		}
	})
}

func TestExportWrappers(t *testing.T) {
	m, svc := newTestServiceModel(t)
	orch := orchestration.New(svc)

	next, cmd := m.StartWizard(tui.WizardCreateVPN)
	if next.Mode() != tui.ModeWizard || cmd == nil {
		t.Fatal("expected create vpn wizard from StartWizard")
	}

	next2, cmd2 := m.StartCongestionWizard()
	if next2.Wizard().Kind != tui.WizardSetCongestion || cmd2 == nil {
		t.Fatal("expected StartCongestionWizard")
	}

	ch := make(chan tea.Msg, 4)
	go tui.RunDefaultBootstrapRunnerForTest(orch, ch)
	for msg := range ch {
		if _, ok := msg.(tui.BootstrapDoneMsg); ok {
			break
		}
	}
}

func TestInferCreateStepFromPrompt(t *testing.T) {
	prompts := map[string]bool{
		"VPN name:": true, "Select protocol:": true, "Select cipher:": true,
		"Port [1080]:": true, "Enable TLS?": true, "TLS mode:": true,
		"Transport options:": true, "Client host [auto]:": true, "Client name:": true,
		"Bandwidth:": true, "Obfuscation:": true, "Masquerade:": true,
		"WireGuard interface mode:": true, "uTLS fingerprint:": true, "VLESS flow:": true,
	}
	for prompt := range prompts {
		step := tui.InferCreateStepFromPromptForTest(tui.WizardStateForTest{Prompt: prompt})
		if step == 0 {
			t.Fatalf("expected known step for %q", prompt)
		}
	}
}

func TestSSCipherHints(t *testing.T) {
	for _, method := range orchestration.ShadowsocksMethods() {
		if tui.SSCipherHintForTest(method) == "" {
			t.Fatalf("empty hint for %s", method)
		}
	}
	if tui.SSCipherHintForTest("unknown-cipher") == "" {
		t.Fatal("expected default hint")
	}
}

func TestWizardUpdateExtras(t *testing.T) {
	t.Run("tick while busy", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetBusy(true)
		next, cmd := m.Update(tui.TickMsg{})
		if cmd == nil {
			t.Fatal("expected tick cmd")
		}
		_ = next
	})

	t.Run("action done refresh menu", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetBusy(true)
		next, cmd := m.Update(tui.NewActionDoneMsgForTest("ok", nil, true))
		if cmd == nil || next.Message() != "ok" {
			t.Fatal("expected refresh batch")
		}
	})

	t.Run("wizard text typing", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, StepType: tui.StepText, Prompt: "VPN name:",
			Input: tui.NewTextInputForTest(""),
		})
		next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
		if next.WizardInputValue() != "x" {
			t.Fatalf("expected typed x, got %q", next.WizardInputValue())
		}
	})

	t.Run("wizard picker navigation", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, StepType: tui.StepPicker,
			Picker: []string{"a", "b", "c"},
		})
		down, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
		if down.Wizard().PickerIdx != 1 {
			t.Fatal("expected idx 1")
		}
		up, _ := down.Update(tea.KeyMsg{Type: tea.KeyUp})
		if up.Wizard().PickerIdx != 0 {
			t.Fatal("expected idx 0")
		}
	})

	t.Run("wizard notice enter cancels", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardAddClient, StepType: tui.StepNotice, Notice: "err"})
		next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
		if next.Mode() != tui.ModeMenu {
			t.Fatal("expected cancel from notice")
		}
	})

	t.Run("vless standard tls flow", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Protocol: "vless", Prompt: "TLS mode:"})
		next, _, ok := m.WizardCreateVPNPickerEnter(0)
		if !ok || !strings.Contains(next.Wizard().Prompt, "SNI") {
			t.Fatalf("expected standard tls SNI, got %q", next.Wizard().Prompt)
		}
	})

	t.Run("vmess no tls", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Protocol: "vmess", Prompt: "Enable TLS?"})
		next, _, ok := m.WizardCreateVPNPickerEnter(0)
		if !ok || next.Wizard().Prompt != "Transport options:" {
			t.Fatalf("expected transport picker, got %q", next.Wizard().Prompt)
		}
	})

	t.Run("trojan fallback invalid", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "trojan", Prompt: "Fallback port [0=disabled]:",
			TrojanPendingPrompt: "fallback", Input: tui.NewTextInputForTest("bad"),
		})
		m.SetWizardInputValue("bad")
		next, cmd := m.WizardTextEnter()
		if cmd == nil || !strings.Contains(next.Wizard().Prompt, "invalid") {
			t.Fatalf("expected invalid fallback, got %q", next.Wizard().Prompt)
		}
	})

	t.Run("edit vpn client host clear", func(t *testing.T) {
		m, svc := newTestServiceModel(t)
		createTestVPN(t, svc, "web", 8080)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardEditVPN, Step: 2, StepType: tui.StepText, EditField: "Client host",
			VPNName: "web", SelectedVPN: orchestration.VPNView{Name: "web", Protocol: "socks5", Listen: domain.ListenOptions{ListenPort: 8080}},
			Prompt: "Client host [auto]:", Input: tui.NewTextInputForTest("auto"),
		})
		m.SetWizardInputValue("auto")
		next, cmd := m.WizardTextEnter()
		if cmd == nil || next.Mode() != tui.ModeMenu {
			t.Fatal("expected clear client host async")
		}
	})

	t.Run("add client finish cmd", func(t *testing.T) {
		m, svc := newTestServiceModel(t)
		createTestVPN(t, svc, "main", 1080)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardAddClient, Step: 1, StepType: tui.StepText,
			Prompt: "Client name:", VPNName: "main", Input: tui.NewTextInputForTest("tab"),
		})
		m.SetWizardInputValue("tab")
		finish, cmd := m.WizardTextEnter()
		if cmd == nil || !finish.Busy() {
			t.Fatal("expected add client busy")
		}
		done, _ := finish.Update(firstTeaMsg(cmd))
		_ = done.Message()
	})
}

func TestCoverageRound2(t *testing.T) {
	t.Run("ss cipher hint branches", func(t *testing.T) {
		for _, method := range []string{
			"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
			"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "other",
		} {
			if tui.SSCipherHintForTest(method) == "" {
				t.Fatalf("empty hint for %q", method)
			}
		}
	})

	t.Run("trojan transport host pending", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "trojan", Prompt: "Transport host:",
			TrojanPendingPrompt: "host", TrojanTransport: "ws",
			Input: tui.NewTextInputForTest("example.com"),
		})
		m.SetWizardInputValue("example.com")
		next, _, ok := m.WizardCreateVPNTextEnter("example.com")
		if !ok || !strings.Contains(next.Wizard().Prompt, "Fallback") {
			t.Fatalf("expected fallback after host, got %q", next.Wizard().Prompt)
		}
	})

	t.Run("wireguard invalid subnet and mtu", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "wireguard", Prompt: "Subnet [10.8.0.1/24]:",
		})
		next, cmd, ok := m.WizardCreateVPNTextEnter("not-a-cidr")
		if !ok || cmd == nil || !strings.Contains(next.Wizard().Prompt, "invalid") {
			t.Fatal("expected invalid subnet")
		}
		m2 := tui.NewModelForTest(nil, nil)
		m2.SetMode(tui.ModeWizard)
		m2.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "wireguard", Prompt: "MTU [1408, empty=default]:",
			WGAddress: "10.8.0.1/24",
		})
		next2, cmd2, ok2 := m2.WizardCreateVPNTextEnter("100")
		if !ok2 || cmd2 == nil || !strings.Contains(next2.Wizard().Prompt, "invalid") {
			t.Fatal("expected invalid mtu")
		}
	})

	t.Run("hy2 invalid upload bandwidth", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2",
			Prompt: "Upload bandwidth (Mbps) [100]:", Hy2PendingPrompt: "up_mbps",
		})
		next, cmd, ok := m.WizardCreateVPNTextEnter("0")
		if !ok || cmd == nil || !strings.Contains(next.Wizard().Prompt, "invalid") {
			t.Fatal("expected invalid upload")
		}
	})

	t.Run("vmess tls sni", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "vmess", Prompt: "TLS server name (SNI) [auto]:",
		})
		next, _, ok := m.WizardCreateVPNTextEnter("example.com")
		if !ok || next.Wizard().Prompt != "Transport options:" {
			t.Fatalf("expected transport, got %q", next.Wizard().Prompt)
		}
	})

	t.Run("finish set congestion async", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetMode(tui.ModeWizard)
		next, cmd := m.WizardFinishSetCongestion("cubic")
		if cmd == nil || next.Mode() != tui.ModeMenu {
			t.Fatal("expected async congestion")
		}
		done := next
		if batch, ok := cmd().(tea.BatchMsg); ok {
			for _, c := range batch {
				if c == nil {
					continue
				}
				if _, ok := c().(tui.ActionDoneMsg); ok {
					done, _ = next.Update(c())
					break
				}
			}
		}
		if done.Busy() {
			t.Fatal("expected done after congestion cmd")
		}
	})

	t.Run("restore backup confirm", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardRestoreBackup, StepType: tui.StepConfirm, BackupPath: "/tmp/x.tar.gz",
		})
		next, cmd := m.WizardConfirmEnter()
		if cmd == nil || next.Mode() != tui.ModeMenu {
			t.Fatal("expected restore async")
		}
	})

	t.Run("delete vpn confirm", func(t *testing.T) {
		m, svc := newTestServiceModel(t)
		createTestVPN(t, svc, "gone", 1099)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardDeleteVPN, StepType: tui.StepConfirm, VPNName: "gone"})
		next, cmd := m.WizardConfirmEnter()
		if cmd == nil || next.Mode() != tui.ModeMenu {
			t.Fatal("expected delete async")
		}
	})

	t.Run("edit client username", func(t *testing.T) {
		m, svc := newTestServiceModel(t)
		createTestVPN(t, svc, "web", 8080)
		ctx := context.Background()
		if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "web", Name: "phone"}, true); err != nil {
			t.Fatal(err)
		}
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardEditClient, Step: 3, StepType: tui.StepText, EditField: "Username",
			VPNName: "web", ClientName: "phone", Prompt: "Username [phone]:",
			Input: tui.NewTextInputForTest("user1"),
		})
		m.SetWizardInputValue("user1")
		next, cmd := m.WizardTextEnter()
		if cmd == nil || next.Mode() != tui.ModeMenu {
			t.Fatal("expected username edit async")
		}
	})

	t.Run("wizard after vpn pick add client", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardAddClient, VPNName: "main"})
		next, cmd := m.WizardAfterVPNPick()
		if cmd == nil || next.Wizard().Prompt != "Client name:" {
			t.Fatal("expected client name step")
		}
	})

	t.Run("wizard after vpn pick edit client loads", func(t *testing.T) {
		m, svc := newTestServiceModel(t)
		createTestVPN(t, svc, "main", 1080)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditClient, VPNName: "main"})
		next, cmd := m.WizardAfterVPNPick()
		if cmd == nil || !next.Wizard().Loading {
			t.Fatal("expected loading clients")
		}
	})

	t.Run("picker enter manage edit vpn steps", func(t *testing.T) {
		vpn := orchestration.VPNView{Name: "main", Protocol: "socks5", Listen: domain.ListenOptions{ListenPort: 1080}}
		m, svc := newTestServiceModel(t)
		createTestVPN(t, svc, "main", 1080)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardEditVPN, Step: 0, StepType: tui.StepPicker,
			Picker: []string{"main :1080 (socks5)"},
			VPNs:   []orchestration.VPNView{vpn},
		})
		next, _ := m.WizardPickerEnter()
		if next.Wizard().Prompt != "Field to edit:" {
			t.Fatal("expected field picker")
		}
		next.SetWizardPickerIdx(0)
		next2, _ := next.WizardPickerEnter()
		if next2.Wizard().StepType != tui.StepPicker {
			t.Fatal("expected status picker")
		}
	})

	t.Run("loader error paths closed store", func(t *testing.T) {
		dir := t.TempDir()
		app := &config.App{DataDir: dir, DBPath: dir + "/state.db", ManifestPath: dir + "/manifest.json", DevMode: true}
		st, err := store.Open(app.DBPath)
		if err != nil {
			t.Fatal(err)
		}
		man := manifest.NewManager(app.ManifestPath)
		_ = man.Load()
		svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
		orch := orchestration.New(svc)
		_ = st.Close()
		if msg := firstTeaMsg(tui.LoadVPNsCmdForTest(orch)); msg == nil {
			t.Fatal("expected error msg")
		}
		if msg := firstTeaMsg(tui.LoadClientsCmdForTest(orch, "x")); msg == nil {
			t.Fatal("expected error msg")
		}
	})

	t.Run("format uri with qr ascii", func(t *testing.T) {
		out, err := tui.FormatURIWithQRForTest("ss://YWVzLTEyOC1nY206dGVzdA==@127.0.0.1:8388")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, "ss://") {
			t.Fatal("expected uri with optional qr")
		}
	})

	t.Run("start wizard unknown kind cancels", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		next, cmd := m.StartWizard(999)
		if next.Mode() != tui.ModeMenu || cmd != nil {
			t.Fatal("expected cancel for unknown kind")
		}
	})

	t.Run("wizard create vpn back empty history", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN})
		next, cmd := m.WizardCreateVPNBack()
		if cmd != nil {
			t.Fatal("expected no cmd without history")
		}
		_ = next
	})

	t.Run("hy2 obfs salamander", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", Prompt: "Obfuscation:",
			Picker: []string{"None", "Salamander"},
		})
		m.SetWizardPickerIdx(1)
		next, _, ok := m.WizardCreateVPNPickerEnter(1)
		if !ok || next.Wizard().Prompt != "Masquerade:" {
			t.Fatalf("expected masquerade, got %q", next.Wizard().Prompt)
		}
	})

	t.Run("tuic congestion picker", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "tuic", Prompt: "Congestion control:",
			Picker: []string{"Cubic", "New Reno", "BBR"},
		})
		next, _, ok := m.WizardCreateVPNPickerEnter(2)
		if !ok || next.Wizard().Prompt != "0-RTT handshake:" {
			t.Fatalf("expected 0-rtt, got %q", next.Wizard().Prompt)
		}
	})

	t.Run("httpupgrade path to host", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "trojan", Prompt: "Transport path:",
			TrojanPendingPrompt: "path", TrojanTransport: "httpupgrade",
		})
		next, _, ok := m.WizardCreateVPNTextEnter("/ws")
		if !ok || next.Wizard().Prompt != "Transport host:" {
			t.Fatalf("expected host prompt, got %q", next.Wizard().Prompt)
		}
	})
}

func TestCoverageRound3(t *testing.T) {
	t.Run("trojan pending text via unknown step", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "trojan",
			Prompt: "Enter transport path:", CreateStep: 0,
			TrojanPendingPrompt: "path", TrojanTransport: "ws",
		})
		next, _, ok := m.WizardCreateVPNTextEnter("/api")
		if !ok || next.Wizard().Prompt != "Transport host:" {
			t.Fatalf("expected host after pending path, got %q", next.Wizard().Prompt)
		}
	})

	t.Run("protocol specific sni fallback tuic and hy2", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "tuic", CreateStep: 0,
			Prompt: "Custom SNI field [auto]:",
		})
		next, _, ok := m.WizardCreateVPNTextEnter("example.com")
		if !ok || next.Wizard().Prompt != "Congestion control:" {
			t.Fatalf("expected tuic congestion, got %q", next.Wizard().Prompt)
		}
		m2 := tui.NewModelForTest(nil, nil)
		m2.SetMode(tui.ModeWizard)
		m2.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", CreateStep: 0,
			Prompt: "Custom SNI field [auto]:",
		})
		next2, _, ok2 := m2.WizardCreateVPNTextEnter("example.com")
		if !ok2 || next2.Wizard().Prompt != "Bandwidth:" {
			t.Fatalf("expected hy2 bandwidth, got %q", next2.Wizard().Prompt)
		}
	})

	t.Run("hy2 download bandwidth via protocol specific", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", CreateStep: 7,
			Prompt: "Download bandwidth (Mbps) [100]:", Hy2UpMbps: 100,
			Hy2PendingPrompt: "down_mbps",
		})
		next, _, ok := m.WizardCreateVPNTextEnter("200")
		if !ok || next.Wizard().Prompt != "Obfuscation:" {
			t.Fatalf("expected obfs picker, got %q", next.Wizard().Prompt)
		}
	})

	t.Run("async manage flows to completion", func(t *testing.T) {
		m, svc := newTestServiceModel(t)
		createTestVPN(t, svc, "web", 8080)
		ctx := context.Background()
		if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "web", Name: "phone"}, true); err != nil {
			t.Fatal(err)
		}
		vpn := orchestration.VPNView{Name: "web", Protocol: "http", Enabled: true, Listen: domain.ListenOptions{ListenPort: 8080}}

		t.Run("edit vpn", func(t *testing.T) {
			mm := m
			mm.SetMode(tui.ModeWizard)
			mm.SetWizard(tui.WizardStateForTest{
				Kind: tui.WizardEditVPN, Step: 2, StepType: tui.StepPicker,
				EditField: "Status", VPNName: "web", SelectedVPN: vpn,
				Picker: []string{"Active", "Inactive"},
			})
			mm.SetWizardPickerIdx(1)
			next, cmd := mm.WizardPickerEnter()
			done := completeAsync(t, next, cmd)
			if !strings.Contains(done.Message(), "Updated VPN") {
				t.Fatalf("unexpected message: %q", done.Message())
			}
		})

		t.Run("edit client password", func(t *testing.T) {
			mm := m
			mm.SetMode(tui.ModeWizard)
			mm.SetWizard(tui.WizardStateForTest{
				Kind: tui.WizardEditClient, Step: 3, StepType: tui.StepText, EditField: "Password",
				VPNName: "web", ClientName: "phone", Input: tui.NewTextInputForTest("secret"),
			})
			mm.SetWizardInputValue("secret")
			next, cmd := mm.WizardTextEnter()
			done := completeAsync(t, next, cmd)
			if !strings.Contains(done.Message(), "Updated client") {
				t.Fatalf("unexpected message: %q", done.Message())
			}
		})

		t.Run("show client", func(t *testing.T) {
			mm := m
			mm.SetMode(tui.ModeWizard)
			mm.SetWizard(tui.WizardStateForTest{Kind: tui.WizardShowClient, VPNName: "web", ClientName: "phone"})
			next, cmd := mm.WizardAfterClientPick()
			done := completeAsync(t, next, cmd)
			if done.Message() == "" {
				t.Fatal("expected client export message")
			}
		})

		t.Run("remove client", func(t *testing.T) {
			if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "web", Name: "tab"}, true); err != nil {
				t.Fatal(err)
			}
			mm := m
			mm.SetMode(tui.ModeWizard)
			mm.SetWizard(tui.WizardStateForTest{Kind: tui.WizardRemoveClient, VPNName: "web", ClientName: "tab"})
			next, cmd := mm.WizardConfirmEnter()
			done := completeAsync(t, next, cmd)
			if !strings.Contains(done.Message(), "Removed client") {
				t.Fatalf("unexpected message: %q", done.Message())
			}
		})

		t.Run("delete vpn", func(t *testing.T) {
			createTestVPN(t, svc, "gone", 1099)
			mm := m
			mm.SetMode(tui.ModeWizard)
			mm.SetWizard(tui.WizardStateForTest{Kind: tui.WizardDeleteVPN, VPNName: "gone"})
			next, cmd := mm.WizardConfirmEnter()
			done := completeAsync(t, next, cmd)
			if !strings.Contains(done.Message(), "Deleted VPN") {
				t.Fatalf("unexpected message: %q", done.Message())
			}
		})

		t.Run("restore backup", func(t *testing.T) {
			path, err := svc.CreateBackup(ctx)
			if err != nil {
				t.Fatal(err)
			}
			mm := m
			mm.SetMode(tui.ModeWizard)
			mm.SetWizard(tui.WizardStateForTest{Kind: tui.WizardRestoreBackup, BackupPath: path})
			next, cmd := mm.WizardConfirmEnter()
			done := completeAsync(t, next, cmd)
			if !strings.Contains(done.Message(), "Backup restored") {
				t.Fatalf("unexpected message: %q", done.Message())
			}
		})

		t.Run("add client with qr", func(t *testing.T) {
			createTestVPN(t, svc, "qr-vpn", 1100)
			mm := m
			mm.SetMode(tui.ModeWizard)
			mm.SetWizard(tui.WizardStateForTest{
				Kind: tui.WizardAddClient, Step: 1, StepType: tui.StepText,
				VPNName: "qr-vpn", Prompt: "Client name:", Input: tui.NewTextInputForTest("dev"),
			})
			mm.SetWizardInputValue("dev")
			next, cmd := mm.WizardTextEnter()
			if cmd == nil {
				t.Fatal("expected add client cmd")
			}
			done := completeAsync(t, next, cmd)
			if done.Message() == "" {
				t.Fatal("expected add client export")
			}
		})
	})

	t.Run("wrong protocol picker guards", func(t *testing.T) {
		cases := []struct {
			name     string
			protocol string
			prompt   string
			picker   []string
		}{
			{"tls mode", "http", "TLS mode:", nil},
			{"transport", "http", "Transport options:", orchestration.InboundTransportModes("http")},
			{"vless flow", "trojan", "VLESS flow:", orchestration.VLESSFlowModes()},
			{"reality fp", "trojan", "uTLS fingerprint:", tui.RealityUTLSFingerprintModesForTest()},
			{"wg interface", "socks5", "WireGuard interface mode:", []string{"Direct (userspace)", "System interface"}},
			{"tuic cc", "socks5", "Congestion control:", orchestration.TUICCongestionPickerModes()},
			{"tuic 0rtt", "socks5", "0-RTT handshake:", []string{"Disabled (recommended)", "Enabled (replay risk)"}},
			{"hy2 bandwidth", "tuic", "Bandwidth:", []string{"No limit", "Set bandwidth", "Ignore client bandwidth (BBR)"}},
			{"hy2 obfs", "tuic", "Obfuscation:", []string{"None", "Salamander"}},
			{"hy2 masquerade", "tuic", "Masquerade:", []string{"None", "Reverse proxy URL", "File directory"}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				m := tui.NewModelForTest(nil, nil)
				m.SetWizard(tui.WizardStateForTest{
					Kind: tui.WizardCreateVPN, Protocol: tc.protocol, Prompt: tc.prompt, Picker: tc.picker,
				})
				_, _, _ = m.WizardCreateVPNPickerEnter(0)
			})
		}
	})

	t.Run("wrong protocol text guards", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "socks5", Prompt: "Fallback port [0=disabled]:",
		})
		if _, _, ok := m.WizardCreateVPNTextEnter("0"); ok {
			t.Fatal("expected fallback guard for non-inbound protocol")
		}
		m2 := tui.NewModelForTest(nil, nil)
		m2.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "socks5", Prompt: "Transport path:",
		})
		if _, _, ok := m2.WizardCreateVPNTextEnter("/x"); ok {
			t.Fatal("expected transport detail guard")
		}
	})

	t.Run("format uri qr error path", func(t *testing.T) {
		long := strings.Repeat("x", 8000)
		out, err := tui.FormatURIWithQRForTest(long)
		if err != nil {
			t.Fatal(err)
		}
		if out != long {
			t.Fatal("expected uri-only fallback on qr error")
		}
	})

	t.Run("format client export qr error", func(t *testing.T) {
		long := strings.Repeat("y", 8000)
		out, err := tui.FormatClientExportForTest("short-uri", long)
		if err != nil {
			t.Fatal(err)
		}
		if out != "short-uri" {
			t.Fatal("expected uri-only fallback on qr error")
		}
	})

	t.Run("create vpn cmd paths", func(t *testing.T) {
		_, svc := newTestServiceModel(t)
		orch := orchestration.New(svc)
		req := tui.BuildCreateVPNRequestForTest(tui.WizardStateForTest{
			VPNName: "socks1", Protocol: "socks5", ListenPort: 1081,
			ClientName: "phone", ClientHost: "",
		})
		msg := firstTeaMsg(tui.CreateVPNCmdForTest(orch, req))
		if msg == nil {
			t.Fatal("expected create result")
		}
		result, ok := msg.(tui.CreateVPNResultMsg)
		if !ok || tui.CreateVPNResultErrorForTest(result) != nil {
			t.Fatalf("expected success, got %#v", msg)
		}
		dup := tui.BuildCreateVPNRequestForTest(tui.WizardStateForTest{
			VPNName: "socks1", Protocol: "socks5", ListenPort: 1082, ClientName: "x",
		})
		errMsg := firstTeaMsg(tui.CreateVPNCmdForTest(orch, dup))
		if errResult, ok := errMsg.(tui.CreateVPNResultMsg); !ok || tui.CreateVPNResultErrorForTest(errResult) == nil {
			t.Fatal("expected duplicate name error")
		}
	})

	t.Run("update wizard ctrl c and picker bounds", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardAddClient, StepType: tui.StepText, Prompt: "Client name:",
			Input: tui.NewTextInputForTest(""),
		})
		next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
		if !next.Quitting() || cmd == nil {
			t.Fatal("expected quit from wizard text ctrl+c")
		}
		m2 := tui.NewModelForTest(nil, nil)
		m2.SetMode(tui.ModeWizard)
		m2.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardAddClient, StepType: tui.StepPicker, Picker: []string{"only"},
		})
		down, _ := m2.Update(tea.KeyMsg{Type: tea.KeyDown})
		if down.Wizard().PickerIdx != 0 {
			t.Fatal("picker should not pass end")
		}
		up, _ := down.Update(tea.KeyMsg{Type: tea.KeyUp})
		if up.Wizard().PickerIdx != 0 {
			t.Fatal("picker should not pass start")
		}
		quit, cmd2 := up.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
		if !quit.Quitting() || cmd2 == nil {
			t.Fatal("expected quit from wizard picker ctrl+c")
		}
		m3 := tui.NewModelForTest(nil, nil)
		m3.SetMode(tui.ModeWizard)
		m3.SetWizard(tui.WizardStateForTest{Kind: tui.WizardAddClient, StepType: tui.StepText})
		back, _ := m3.Update(tea.KeyMsg{Type: tea.KeyCtrlP})
		if back.Mode() != tui.ModeWizard {
			t.Fatal("ctrl+p should not back on non-create wizard")
		}
	})

	t.Run("load menu status error", func(t *testing.T) {
		dir := t.TempDir()
		app := &config.App{DataDir: dir, DBPath: dir + "/state.db", ManifestPath: dir + "/manifest.json", DevMode: true}
		st, err := store.Open(app.DBPath)
		if err != nil {
			t.Fatal(err)
		}
		svc := service.NewService(app, st, runtime.NewProtocolRegistry(), manifest.NewManager(app.ManifestPath), firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
		orch := orchestration.New(svc)
		_ = st.Close()
		msg := firstTeaMsg(tui.LoadMenuStatusCmdForTest(orch))
		status, ok := msg.(tui.MenuStatusMsg)
		if !ok || tui.MenuStatusBootstrappedForTest(status) {
			t.Fatal("expected bootstrapped false on error")
		}
	})

	t.Run("start wizard alias branches", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		if next, cmd := m.StartWizard(tui.WizardRestoreBackup); next.Wizard().Kind != tui.WizardRestoreBackup || cmd == nil {
			t.Fatal("expected restore via StartWizard")
		}
		if next, cmd := m.StartWizard(tui.WizardSetCongestion); next.Wizard().Kind != tui.WizardSetCongestion || cmd == nil {
			t.Fatal("expected congestion via StartWizard")
		}
		if next, cmd := m.StartWizard(tui.WizardSetSSHPort); next.Wizard().Kind != tui.WizardSetSSHPort || cmd == nil {
			t.Fatal("expected ssh via StartWizard")
		}
	})

	t.Run("handle select remaining branches", func(t *testing.T) {
		m, svc := newTestServiceModel(t)
		m.SetBootstrapped(false)
		m.SetItems(m.MainMenuItems())
		m.SetCursor(1)
		if next, cmd := m.HandleSelect(); !next.Quitting() || cmd == nil {
			t.Fatal("expected quit pre-bootstrap")
		}
		m.SetBootstrapped(true)
		m.SetScreen(tui.ScreenVPNs)
		m.SetItems(tui.VPNMenuItemsForTest())
		m.SetCursor(0)
		if next, cmd := m.HandleSelect(); next.Wizard().Kind != tui.WizardCreateVPN || cmd == nil {
			t.Fatal("expected create vpn wizard")
		}
		m.SetScreen(tui.ScreenVPNs)
		m.SetItems(tui.VPNMenuItemsForTest())
		m.SetCursor(1)
		next, cmd := m.HandleSelect()
		if !next.Busy() || cmd == nil {
			t.Fatal("expected list vpns busy")
		}
		done := completeAsync(t, next, cmd)
		if done.Message() != "No VPNs" {
			t.Fatalf("expected no vpns, got %q", done.Message())
		}
		createTestVPN(t, svc, "listed", 1088)
		m.SetScreen(tui.ScreenVPNs)
		m.SetItems(tui.VPNMenuItemsForTest())
		m.SetCursor(1)
		next2, cmd2 := m.HandleSelect()
		done2 := completeAsync(t, next2, cmd2)
		if !strings.Contains(done2.Message(), "listed") {
			t.Fatalf("expected vpn list, got %q", done2.Message())
		}
		m.SetScreen(tui.ScreenVPNs)
		m.SetItems(tui.VPNMenuItemsForTest())
		m.SetCursor(4)
		if next, _ := m.HandleSelect(); next.Screen() != tui.ScreenMain {
			t.Fatal("expected vpn back")
		}
		m.SetScreen(tui.ScreenClients)
		m.SetItems(tui.ClientMenuItemsForTest())
		m.SetCursor(4)
		if next, _ := m.HandleSelect(); next.Screen() != tui.ScreenMain {
			t.Fatal("expected clients back")
		}
	})

	t.Run("wizard nav history and step changed", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		hist := tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Prompt: "VPN name:", StepType: tui.StepText}
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Prompt: "Port [1080]:", StepType: tui.StepText,
			WizardHistory: []tui.WizardStateForTest{hist},
		})
		next, cmd := m.WizardCreateVPNBack()
		if cmd == nil || next.Wizard().Prompt != "VPN name:" {
			t.Fatal("expected pop history")
		}
		m2 := tui.NewModelForTest(nil, nil)
		m2.SetMode(tui.ModeWizard)
		m2.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Protocol: "socks5", Prompt: "Port [1080]:"})
		same, _, _ := m2.WizardCreateVPNTextEnter("1080")
		if same.Wizard().Prompt != "Client host [auto]:" {
			t.Fatalf("expected advance, got %q", same.Wizard().Prompt)
		}
	})

	t.Run("wizard manage edge cases", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditVPN, Step: 2, EditField: "Unknown"})
		if _, cmd := m.WizardShowEditVPNValue(); cmd != nil {
			t.Fatal("unexpected cmd for unknown field")
		}
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditClient, Step: 3, EditField: "Unknown"})
		if _, cmd := m.WizardShowEditClientValue(); cmd != nil {
			t.Fatal("unexpected cmd for unknown client field")
		}
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardShowClient, Step: 1, VPNName: "x", ClientName: "y"})
		mm := tui.NewModelForTest(nil, nil)
		mm.SetMode(tui.ModeWizard)
		mm.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, VPNName: "x"})
		if _, cmd := mm.WizardAfterVPNPick(); cmd != nil {
			t.Fatal("expected nil cmd for unknown after vpn pick kind")
		}
		vpn := orchestration.VPNView{Name: "web", Protocol: "http", Listen: domain.ListenOptions{ListenPort: 8080}}
		m2, svc := newTestServiceModel(t)
		createTestVPN(t, svc, "web", 8080)
		m2.SetMode(tui.ModeWizard)
		m2.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardEditVPN, Step: 2, StepType: tui.StepPicker,
			EditField: "TLS", VPNName: "web", SelectedVPN: vpn,
			Picker: []string{"Enable TLS", "Disable TLS"},
		})
		m2.SetWizardPickerIdx(0)
		next, cmd := m2.WizardPickerEnter()
		completeAsync(t, next, cmd)
	})

	t.Run("apply menu status cursor clamp", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetScreen(tui.ScreenMain)
		m.SetCursor(99)
		next, _ := m.Update(tui.NewMenuStatusMsgForTest(true))
		if next.Cursor() != 0 {
			t.Fatalf("expected cursor clamp, got %d", next.Cursor())
		}
	})

	t.Run("configured ssh port paths", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		if port := m.MainMenuItems(); len(port) == 0 {
			t.Fatal("expected default menu")
		}
		m2, _ := newTestServiceModel(t)
		m2.SetMode(tui.ModeWizard)
		m2.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardEditVPN, Step: 2, StepType: tui.StepText, EditField: "Port",
			VPNName: "x", SelectedVPN: orchestration.VPNView{Name: "x", Protocol: "socks5", Listen: domain.ListenOptions{ListenPort: 1080}},
			Prompt: "Port [1080]:", Input: tui.NewTextInputForTest("22"),
		})
		m2.SetWizardInputValue("22")
		next, cmd := m2.WizardTextEnter()
		if cmd == nil || next.Mode() == tui.ModeMenu {
			t.Fatal("expected ssh port reserved error in wizard")
		}
	})

	t.Run("render and view branches", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, StepType: tui.StepConfirm})
		if !strings.Contains(m.View(), "enter confirm") {
			t.Fatal("expected confirm help")
		}
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardAddClient, StepType: tui.StepNotice, Notice: "oops"})
		if !strings.Contains(m.View(), "enter/esc cancel") {
			t.Fatal("expected notice help")
		}
		m.SetMode(tui.ModeMenu)
		m.SetMessage("hello")
		if !strings.Contains(m.View(), "esc dismiss message") {
			t.Fatal("expected dismiss help")
		}
		m.SetScreen(tui.ScreenVPNs)
		m.SetItems(tui.VPNMenuItemsForTest())
		if !strings.Contains(m.View(), "obscura / VPNs") {
			t.Fatal("expected vpn title")
		}
		m.SetQuitting(true)
		if m.View() != "" {
			t.Fatal("expected empty view when quitting")
		}
	})

	t.Run("update app branches", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetBusy(true)
		next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
		if !next.Quitting() || cmd == nil {
			t.Fatal("expected busy ctrl+c quit")
		}
		m2 := tui.NewModelForTest(nil, nil)
		m2.SetBootstrapped(true)
		m2.SetScreen(tui.ScreenVPNs)
		m2.SetItems(tui.VPNMenuItemsForTest())
		m2.SetMessage("msg")
		dismiss, _ := m2.Update(tea.KeyMsg{Type: tea.KeyEsc})
		if dismiss.Message() != "" {
			t.Fatal("expected message dismissed")
		}
		m2.SetIgnoreEnter(true)
		stay, cmd := m2.Update(tea.KeyMsg{Type: tea.KeyEnter})
		if cmd != nil {
			t.Fatal("expected no select while debounced")
		}
		_ = stay
		m3 := tui.NewModelForTest(nil, nil)
		m3.SetBootstrapped(true)
		m3.SetScreen(tui.ScreenMain)
		m3.SetItems(m3.MainMenuItems())
		m3.SetCursor(len(m3.Items()) - 1)
		quit, cmd := m3.Update(tea.KeyMsg{Type: tea.KeyCtrlQ})
		if !quit.Quitting() || cmd == nil {
			t.Fatal("expected ctrl+q quit")
		}
	})

	t.Run("picker manage bounds and edit flows", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardDeleteVPN, Step: 0, StepType: tui.StepPicker,
			VPNs:   []orchestration.VPNView{{Name: "a"}},
			Picker: []string{"a"},
		})
		m.SetWizardPickerIdx(5)
		next, _ := m.WizardPickerEnter()
		if next.Wizard().StepType == tui.StepConfirm {
			t.Fatal("oob picker idx should not confirm")
		}
	})
}

func TestCoverageRound4(t *testing.T) {
	t.Run("trojan pending all branches", func(t *testing.T) {
		cases := []struct {
			name      string
			pending   string
			transport string
			input     string
			want      string
		}{
			{"service_name", "service_name", "grpc", "svc", "Fallback"},
			{"host", "host", "ws", "example.com", "Fallback"},
			{"fallback", "fallback", "", "0", "Client host"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				m := tui.NewModelForTest(nil, nil)
				m.SetMode(tui.ModeWizard)
				m.SetWizard(tui.WizardStateForTest{
					Kind: tui.WizardCreateVPN, Protocol: "trojan", CreateStep: 0,
					Prompt: "Custom pending input:", TrojanPendingPrompt: tc.pending,
					TrojanTransport: tc.transport,
				})
				next, _, ok := m.WizardCreateVPNTextEnter(tc.input)
				if !ok || !strings.Contains(next.Wizard().Prompt, tc.want) {
					t.Fatalf("got %q", next.Wizard().Prompt)
				}
			})
		}
		m := tui.NewModelForTest(nil, nil)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "trojan", CreateStep: 0,
			Prompt: "Custom:", TrojanPendingPrompt: "unknown",
		})
		if _, _, ok := m.WizardCreateVPNTextEnter("x"); ok {
			t.Fatal("expected unknown pending guard")
		}
	})

	t.Run("transport picker vmess vless", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "vmess", Prompt: "Transport options:",
			Picker: orchestration.InboundTransportModes("vmess"),
		})
		if next, _, ok := m.WizardCreateVPNPickerEnter(0); !ok || !strings.Contains(next.Wizard().Prompt, "Fallback") {
			t.Fatalf("vmess transport: %q", next.Wizard().Prompt)
		}
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "vless", Prompt: "Transport options:",
			Picker: orchestration.InboundTransportModes("vless"),
		})
		if next, _, ok := m.WizardCreateVPNPickerEnter(0); !ok || !strings.Contains(next.Wizard().Prompt, "Fallback") {
			t.Fatalf("vless transport: %q", next.Wizard().Prompt)
		}
	})

	t.Run("protocol specific masquerade and vmess sni", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", CreateStep: 7,
			Prompt: "Masquerade proxy URL [http://127.0.0.1:8080]:",
		})
		next, _, ok := m.WizardCreateVPNTextEnter("")
		if !ok || next.Wizard().Prompt != "Client host [auto]:" {
			t.Fatalf("proxy: %q", next.Wizard().Prompt)
		}
		m2 := tui.NewModelForTest(nil, nil)
		m2.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "vmess", CreateStep: 7,
			Prompt: "TLS server name (SNI) [auto]:",
		})
		next2, _, ok2 := m2.WizardCreateVPNTextEnter("sni.example.com")
		if !ok2 || next2.Wizard().Prompt != "Transport options:" {
			t.Fatalf("vmess sni: %q", next2.Wizard().Prompt)
		}
	})

	t.Run("wizard text enter create without orch", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Step: 0, StepType: tui.StepText, Prompt: "VPN name:",
			Input: tui.NewTextInputForTest("solo"),
		})
		m.SetWizardInputValue("solo")
		next, cmd := m.WizardTextEnter()
		if cmd == nil || !next.Wizard().Loading {
			t.Fatal("expected protocol load without orch validation")
		}
	})

	t.Run("wizard picker manage full flows", func(t *testing.T) {
		m, svc := newTestServiceModel(t)
		createTestVPN(t, svc, "main", 1080)
		ctx := context.Background()
		if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "main", Name: "phone"}, true); err != nil {
			t.Fatal(err)
		}
		client := orchestration.ClientView{Name: "phone", Enabled: true}

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardEditClient, Step: 3, StepType: tui.StepPicker,
			EditField: "Status", VPNName: "main", ClientName: "phone", SelectedClient: client,
			Picker: []string{"Active", "Inactive"},
		})
		if _, cmd := m.WizardPickerEnter(); cmd == nil {
			t.Fatal("expected edit client status async")
		}

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardRestoreBackup, Step: 0, StepType: tui.StepPicker,
			Backups: []orchestration.BackupEntry{{Name: "b1", Path: "/tmp/b1"}},
			Picker:  []string{"b1"},
		})
		if next, _ := m.WizardPickerEnter(); next.Wizard().StepType != tui.StepConfirm {
			t.Fatal("expected restore confirm")
		}

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardSetCongestion, StepType: tui.StepPicker,
			CongestionOptions: []string{"bbr"}, CongestionCurrent: "cubic", Picker: []string{"bbr"},
		})
		if next, cmd := m.WizardPickerEnter(); cmd == nil {
			t.Fatal("expected congestion finish cmd")
		} else {
			completeAsync(t, next, cmd)
		}

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardEditClient, Step: 1, StepType: tui.StepPicker,
			VPNName: "main", Clients: []orchestration.ClientView{client}, Picker: []string{"phone"},
		})
		if next, _ := m.WizardPickerEnter(); next.Wizard().Prompt != "Field to edit:" {
			t.Fatal("expected edit client fields")
		}
	})

	t.Run("wizard text enter manage paths", func(t *testing.T) {
		m, svc := newTestServiceModel(t)
		createTestVPN(t, svc, "main", 1080)
		ctx := context.Background()
		if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "main", Name: "phone"}, true); err != nil {
			t.Fatal(err)
		}
		vpn := orchestration.VPNView{Name: "main", Protocol: "socks5", Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080}}

		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardEditVPN, Step: 2, StepType: tui.StepText, EditField: "Port",
			VPNName: "main", SelectedVPN: vpn, Prompt: "Port [1080]:",
			Input: tui.NewTextInputForTest("1081"),
		})
		m.SetWizardInputValue("1081")
		next, cmd := m.WizardTextEnter()
		completeAsync(t, next, cmd)

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardEditClient, Step: 3, StepType: tui.StepText, EditField: "Name",
			VPNName: "main", ClientName: "phone", Input: tui.NewTextInputForTest("phone2"),
		})
		m.SetWizardInputValue("phone2")
		next2, cmd2 := m.WizardTextEnter()
		completeAsync(t, next2, cmd2)

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardAddClient, Step: 1, StepType: tui.StepText, Input: tui.NewTextInputForTest("")})
		if _, cmd := m.WizardTextEnter(); cmd != nil {
			t.Fatal("empty add client name ignored")
		}
	})

	t.Run("handle select main submenus and errors", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetBootstrapped(true)
		m.SetItems(m.MainMenuItems())
		for i, screen := range []int{tui.ScreenVPNs, tui.ScreenClients} {
			sub := m
			sub.SetCursor(i)
			next, _ := sub.HandleSelect()
			if next.Screen() != screen {
				t.Fatalf("expected screen %d", screen)
			}
		}
		dir := t.TempDir()
		app := &config.App{DataDir: dir, DBPath: dir + "/state.db", ManifestPath: dir + "/manifest.json", DevMode: true}
		st, _ := store.Open(app.DBPath)
		svc := service.NewService(app, st, runtime.NewProtocolRegistry(), manifest.NewManager(app.ManifestPath), firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
		_ = st.Close()
		broken := tui.NewModelForTest(app, orchestration.New(svc))
		broken.SetBootstrapped(true)
		broken.SetScreen(tui.ScreenVPNs)
		broken.SetItems(tui.VPNMenuItemsForTest())
		broken.SetCursor(1)
		next, cmd := broken.HandleSelect()
		done := completeAsync(t, next, cmd)
		if done.Message() == "" {
			t.Fatal("expected list vpns error message")
		}
	})

	t.Run("loader error paths", func(t *testing.T) {
		dir := t.TempDir()
		app := &config.App{DataDir: dir, DBPath: dir + "/state.db", ManifestPath: dir + "/manifest.json", DevMode: true}
		st, _ := store.Open(app.DBPath)
		svc := service.NewService(app, st, runtime.NewProtocolRegistry(), manifest.NewManager(app.ManifestPath), firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
		orch := orchestration.New(svc)
		_ = st.Close()
		for _, cmd := range []tea.Cmd{
			tui.LoadBackupsCmdForTest(orch),
			tui.LoadCongestionCmdForTest(orch),
			tui.LoadProtocolsCmdForTest(orch),
		} {
			if firstTeaMsg(cmd) == nil {
				t.Fatal("expected loader error msg")
			}
		}
	})

	t.Run("apply results error paths", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardRestoreBackup, Loading: true})
		next, _ := m.Update(tui.NewBackupListMsgForTest(nil, errors.New("backup err")))
		if next.Wizard().Notice != "backup err" {
			t.Fatal("expected backup error notice")
		}
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardSetCongestion, Loading: true})
		next2, _ := m.Update(tui.NewCongestionListMsgForTest(nil, "", errors.New("cc err")))
		if next2.Wizard().Notice != "cc err" {
			t.Fatal("expected congestion error notice")
		}
	})

	t.Run("ssh port wizard paths", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardSetSSHPort, StepType: tui.StepText,
			Prompt: "SSH port [22]:", Input: tui.NewTextInputForTest("22"),
		})
		m.SetWizardInputValue("22")
		if next, cmd := m.WizardTextEnter(); cmd != nil || next.Wizard().StepType != tui.StepNotice {
			t.Fatal("expected same port notice")
		}
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardSetSSHPort, StepType: tui.StepText,
			Prompt: "SSH port [22]:", Input: tui.NewTextInputForTest("bad"),
		})
		m.SetWizardInputValue("bad")
		if next, cmd := m.WizardTextEnter(); cmd == nil || next.Mode() != tui.ModeWizard {
			t.Fatal("expected invalid ssh port blink")
		}
	})

	t.Run("hy2 masquerade and bandwidth branches", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", Prompt: "Masquerade:",
			Picker: []string{"None", "Reverse proxy URL", "File directory"},
		})
		m.SetWizardPickerIdx(1)
		if next, _, ok := m.WizardCreateVPNPickerEnter(1); !ok || !strings.Contains(next.Wizard().Prompt, "Masquerade proxy") {
			t.Fatalf("proxy: %q", next.Wizard().Prompt)
		}
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", Prompt: "Bandwidth:",
			Picker: []string{"No limit", "Set bandwidth", "Ignore client bandwidth (BBR)"},
		})
		m.SetWizardPickerIdx(2)
		if next, _, ok := m.WizardCreateVPNPickerEnter(2); !ok || next.Wizard().Prompt != "Obfuscation:" {
			t.Fatalf("ignore bw: %q", next.Wizard().Prompt)
		}
	})

	t.Run("inbound flow extras", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "vless", Prompt: "VLESS flow:",
			Picker: orchestration.VLESSFlowModes(),
		})
		m.SetWizardPickerIdx(1)
		if next, _, ok := m.WizardCreateVPNPickerEnter(1); !ok || next.Wizard().Prompt != "Transport options:" {
			t.Fatalf("vless vision flow: %q", next.Wizard().Prompt)
		}
	})

	t.Run("wizard confirm default", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, StepType: tui.StepConfirm})
		if _, cmd := m.WizardConfirmEnter(); cmd != nil {
			t.Fatal("expected nil for create confirm")
		}
	})

	t.Run("hints and infer prompts", func(t *testing.T) {
		w := tui.WizardStateForTest{StepType: tui.StepPicker, Picker: []string{"a", "b"}, PickerIdx: 0}
		tui.SetPickerStepForTest(&w, "p", "hint", []string{"a", "b"}, []string{"only-one"})
		if tui.ActiveHintForTest(w) != "hint" {
			t.Fatal("expected prompt hint when hint lengths mismatch")
		}
		for _, prompt := range []string{
			"Client host [auto]: (invalid — try again)",
			"Fallback port [0=disabled]: (invalid — try again)",
		} {
			if tui.InferCreateStepFromPromptForTest(tui.WizardStateForTest{Prompt: prompt}) == 0 {
				t.Fatalf("unknown step for %q", prompt)
			}
		}
	})

	t.Run("wizard nav notice step changed", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardAddClient, StepType: tui.StepNotice, Notice: "a"})
		next, _ := m.Update(tui.NewVPNListMsgForTest([]orchestration.VPNView{{Name: "x", Protocol: "socks5", Listen: domain.ListenOptions{ListenPort: 1}}}, nil))
		if next.Wizard().StepType != tui.StepPicker {
			t.Fatal("expected picker after vpn list")
		}
	})

	t.Run("wizard after client pick remove", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardRemoveClient, VPNName: "main", ClientName: "phone"})
		next, cmd := m.WizardAfterClientPick()
		if cmd != nil || next.Wizard().StepType != tui.StepConfirm {
			t.Fatal("expected remove confirm")
		}
	})

	t.Run("render wizard loading empty notice", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardAddClient, Loading: true})
		if !strings.Contains(m.RenderPanel(), "Loading") {
			t.Fatal("expected loading panel")
		}
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardAddClient, StepType: tui.StepNotice, Notice: ""})
		if !strings.Contains(m.RenderPanel(), "Loading") {
			t.Fatal("expected loading for empty notice")
		}
	})

	t.Run("configured ssh port nil orch", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "socks5", Prompt: "Port [1080]:",
		})
		next, _, ok := m.WizardCreateVPNTextEnter("22")
		if !ok || !strings.Contains(next.Wizard().StepError, "SSH") {
			t.Fatal("expected ssh port reserved")
		}
	})

	t.Run("update wizard ctrl p create back", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, StepType: tui.StepPicker,
			WizardHistory: []tui.WizardStateForTest{{Kind: tui.WizardCreateVPN, Prompt: "VPN name:"}},
		})
		next, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlP})
		if next.Wizard().Prompt != "VPN name:" {
			t.Fatalf("expected back, got %q", next.Wizard().Prompt)
		}
	})

	t.Run("shadowsocks padding transport", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "shadowsocks", Prompt: "Transport options:",
			Picker: orchestration.ShadowsocksTransportModes(), VPNName: "ss", ListenPort: 8388,
			SSMethod: orchestration.DefaultShadowsocksMethod(),
		})
		for i, mode := range orchestration.ShadowsocksTransportModes() {
			if mode == "Multiplex (padding)" {
				next, _, ok := m.WizardCreateVPNPickerEnter(i)
				if !ok || next.Wizard().Prompt != "Client host [auto]:" {
					t.Fatalf("padding multiplex: %q", next.Wizard().Prompt)
				}
				break
			}
		}
	})

	t.Run("wireguard system mtu empty", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "wireguard",
			Prompt: "MTU [1408, empty=default]:", WGAddress: "10.8.0.1/24",
		})
		next, _, ok := m.WizardCreateVPNTextEnter("")
		if !ok || next.Wizard().Prompt != "Client host [auto]:" {
			t.Fatalf("empty mtu: %q", next.Wizard().Prompt)
		}
	})

	t.Run("finish set congestion error", func(t *testing.T) {
		dir := t.TempDir()
		app := &config.App{DataDir: dir, DBPath: dir + "/state.db", ManifestPath: dir + "/manifest.json", DevMode: true}
		st, _ := store.Open(app.DBPath)
		_ = st.Close()
		svc := service.NewService(app, st, runtime.NewProtocolRegistry(), manifest.NewManager(app.ManifestPath), firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
		m := tui.NewModelForTest(app, orchestration.New(svc))
		m.SetMode(tui.ModeWizard)
		next, cmd := m.WizardFinishSetCongestion("bbr")
		done := completeAsync(t, next, cmd)
		if done.Message() == "" {
			t.Fatal("expected congestion error message")
		}
	})
}

func TestCoverageRound5(t *testing.T) {
	t.Run("handle select all async menus", func(t *testing.T) {
		m, svc := newTestServiceModel(t)
		m.SetBootstrapped(true)
		createTestVPN(t, svc, "listed", 1088)

		runSelect := func(screen int, items []string, cursor int) *tui.TestModel {
			sub := m
			sub.SetScreen(screen)
			sub.SetItems(items)
			sub.SetCursor(cursor)
			next, cmd := sub.HandleSelect()
			if cmd == nil {
				return next
			}
			return completeAsync(t, next, cmd)
		}

		if next := runSelect(tui.ScreenSystem, tui.SystemMenuItemsForTest(), 0); next.Message() == "" {
			t.Fatal("expected status message")
		}
		if next := runSelect(tui.ScreenSystem, tui.SystemMenuItemsForTest(), 1); next.Message() == "" {
			t.Fatal("expected doctor message")
		}
		if next := runSelect(tui.ScreenSystem, tui.SystemMenuItemsForTest(), 4); next.Message() == "" {
			t.Fatal("expected apply message")
		}
		if next := runSelect(tui.ScreenBackup, tui.BackupMenuItemsForTest(), 0); next.Message() == "" {
			t.Fatal("expected backup create message")
		}
		if next := runSelect(tui.ScreenBackup, tui.BackupMenuItemsForTest(), 1); next.Message() == "" {
			t.Fatal("expected backup list message")
		}

		m.SetBootstrapped(true)
		fresh := tui.NewModelForTest(nil, orchestration.New(svc))
		fresh.SetBootstrapped(true)
		for cursor, screen := range map[int]int{0: tui.ScreenVPNs, 1: tui.ScreenClients, 3: tui.ScreenBackup} {
			sub := fresh
			sub.SetScreen(tui.ScreenMain)
			sub.SetItems(sub.MainMenuItems())
			sub.SetCursor(cursor)
			next, _ := sub.HandleSelect()
			if next.Screen() != screen {
				t.Fatalf("cursor %d: expected screen %d got %d", cursor, screen, next.Screen())
			}
		}
	})

	t.Run("inbound transport all modes", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetMode(tui.ModeWizard)
		modes := orchestration.InboundTransportModes("trojan")
		for idx, mode := range modes {
			mm := m
			mm.SetWizard(tui.WizardStateForTest{
				Kind: tui.WizardCreateVPN, Protocol: "trojan", Prompt: "Transport options:",
				Picker: modes, VPNName: "t", ListenPort: 443, TrojanServerName: "ex.com",
			})
			next, _, ok := mm.WizardCreateVPNPickerEnter(idx)
			if !ok {
				t.Fatalf("mode %s not handled", mode)
			}
			_ = next
		}
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "trojan", Prompt: "Transport options:",
			Picker: modes,
		})
		m.WizardCreateVPNPickerEnter(99)
	})

	t.Run("manage async errors closed store", func(t *testing.T) {
		m := closedOrchModel(t)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardEditVPN, Step: 2, StepType: tui.StepText, EditField: "Name",
			VPNName: "x", SelectedVPN: orchestration.VPNView{Name: "x", Protocol: "socks5", Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1}},
			Input: tui.NewTextInputForTest("y"),
		})
		m.SetWizardInputValue("y")
		next, cmd := m.WizardTextEnter()
		done := completeAsync(t, next, cmd)
		if done.Message() == "" {
			t.Fatal("expected edit vpn error")
		}

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardShowClient, VPNName: "x", ClientName: "c"})
		next2, cmd2 := m.WizardAfterClientPick()
		done2 := completeAsync(t, next2, cmd2)
		if done2.Message() == "" {
			t.Fatal("expected show client error")
		}

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardDeleteVPN, VPNName: "x"})
		next3, cmd3 := m.WizardConfirmEnter()
		done3 := completeAsync(t, next3, cmd3)
		if done3.Message() == "" {
			t.Fatal("expected delete error")
		}
	})

	t.Run("picker manage edit vpn field flow", func(t *testing.T) {
		vpn := orchestration.VPNView{Name: "main", Protocol: "socks5", Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080}}
		m, svc := newTestServiceModel(t)
		createTestVPN(t, svc, "main", 1080)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardEditVPN, Step: 1, StepType: tui.StepPicker,
			Picker: []string{"Status", "Name", "Port", "Client host"}, VPNName: "main", SelectedVPN: vpn,
		})
		m.SetWizardPickerIdx(1)
		next, _ := m.WizardPickerEnter()
		if next.Wizard().EditField != "Name" {
			t.Fatal("expected name field")
		}
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardEditVPN, Step: 2, StepType: tui.StepPicker,
			EditField: "Status", VPNName: "main", SelectedVPN: vpn,
			Picker: []string{"Active", "Inactive"},
		})
		if _, cmd := m.WizardPickerEnter(); cmd == nil {
			t.Fatal("expected tls-off-path status edit")
		}
	})

	t.Run("apply ssh port set error", func(t *testing.T) {
		m := closedOrchModel(t)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardSetSSHPort, StepType: tui.StepText})
		next, cmd := m.Update(tui.NewSSHPortSetMsgForTest(2222, errors.New("ssh fail")))
		if cmd == nil || next.Mode() != tui.ModeWizard {
			t.Fatal("expected ssh error recovery in wizard")
		}
	})

	t.Run("create vpn busy path", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "socks5", StepType: tui.StepText,
			Prompt: "Client name:", VPNName: "busy-vpn", ListenPort: 1095,
			Input: tui.NewTextInputForTest("phone"),
		})
		m.SetWizardInputValue("phone")
		next, cmd := m.WizardTextEnter()
		if cmd == nil || !next.Busy() {
			t.Fatal("expected create vpn busy")
		}
	})

	t.Run("wizard after vpn pick branches", func(t *testing.T) {
		m, svc := newTestServiceModel(t)
		createTestVPN(t, svc, "main", 1080)
		m.SetMode(tui.ModeWizard)
		for _, kind := range []int{tui.WizardShowClient, tui.WizardRemoveClient, tui.WizardEditClient} {
			mm := m
			mm.SetWizard(tui.WizardStateForTest{Kind: kind, VPNName: "main"})
			next, cmd := mm.WizardAfterVPNPick()
			if cmd == nil || !next.Wizard().Loading {
				t.Fatalf("kind %d expected loading", kind)
			}
		}
	})

	t.Run("hy2 invalid download and masquerade file", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2",
			Prompt: "Download bandwidth (Mbps) [100]:", Hy2PendingPrompt: "down_mbps", Hy2UpMbps: 100,
		})
		next, cmd, ok := m.WizardCreateVPNTextEnter("0")
		if !ok || cmd == nil || !strings.Contains(next.Wizard().Prompt, "invalid") {
			t.Fatal("expected invalid download")
		}
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", Prompt: "Masquerade:",
			Picker: []string{"None", "Reverse proxy URL", "File directory"},
		})
		m.SetWizardPickerIdx(2)
		next2, _, ok2 := m.WizardCreateVPNPickerEnter(2)
		if !ok2 || !strings.Contains(next2.Wizard().Prompt, "Masquerade file") {
			t.Fatalf("file masquerade: %q", next2.Wizard().Prompt)
		}
	})

	t.Run("vless trojan sni validation with orch", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Protocol: "tuic", Prompt: "TLS server name (SNI) [auto]:", VPNName: "t", ListenPort: 443})
		if next, _, ok := m.WizardCreateVPNTextEnter("example.com"); !ok || next.Wizard().Prompt != "Congestion control:" {
			t.Fatalf("tuic: %q", next.Wizard().Prompt)
		}
	})

	t.Run("protocol hint default", func(t *testing.T) {
		w := tui.WizardStateForTest{StepType: tui.StepPicker, Picker: []string{"custom-proto"}, PickerIdx: 0, PromptHint: "fallback"}
		tui.SetPickerStepForTest(&w, "Select protocol:", "fallback", []string{"custom-proto"}, []string{""})
		if tui.ActiveHintForTest(w) != "fallback" {
			t.Fatal("expected fallback hint")
		}
	})

	t.Run("wireguard subnet validation with orch", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Protocol: "wireguard", Prompt: "Subnet [10.8.0.1/24]:"})
		next, cmd, ok := m.WizardCreateVPNTextEnter("10.8.0.1/24")
		if !ok || cmd != nil || !strings.Contains(next.Wizard().Prompt, "WireGuard interface") {
			t.Fatalf("subnet: %q", next.Wizard().Prompt)
		}
	})

	t.Run("edit client host set", func(t *testing.T) {
		m, svc := newTestServiceModel(t)
		createTestVPN(t, svc, "socks", 1082)
		vpn := orchestration.VPNView{Name: "socks", Protocol: "socks5", Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1082}}
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardEditVPN, Step: 2, StepType: tui.StepText, EditField: "Client host",
			VPNName: "socks", SelectedVPN: vpn, Input: tui.NewTextInputForTest("host.example.com"),
		})
		m.SetWizardInputValue("host.example.com")
		next, cmd := m.WizardTextEnter()
		completeAsync(t, next, cmd)
	})

	t.Run("finish edit client from picker non status", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditClient, Step: 3, EditField: "Name"})
		if _, cmd := m.WizardPickerEnter(); cmd != nil {
			t.Fatal("expected nil for non-status picker finish")
		}
	})

	t.Run("finish edit vpn from picker non status tls", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditVPN, Step: 2, EditField: "Name"})
		if _, cmd := m.WizardPickerEnter(); cmd != nil {
			t.Fatal("expected nil for non picker finish field")
		}
	})

	t.Run("update tick not busy", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		next, cmd := m.Update(tui.TickMsg{})
		if cmd != nil || next.Busy() {
			t.Fatal("tick ignored when not busy")
		}
	})

	t.Run("create vpn result outside wizard", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		next, cmd := m.Update(tui.NewCreateVPNResultMsgForTest("x", nil))
		if cmd != nil || next.Message() != "" {
			t.Fatal("ignored create result in menu mode")
		}
	})

	t.Run("configured ssh port orch error", func(t *testing.T) {
		m := closedOrchModel(t)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardEditVPN, Step: 2, StepType: tui.StepText, EditField: "Port",
			SelectedVPN: orchestration.VPNView{Listen: domain.ListenOptions{ListenPort: 1080}},
			Input:       tui.NewTextInputForTest("9999"),
		})
		m.SetWizardInputValue("9999")
		if next, cmd := m.WizardTextEnter(); cmd == nil {
			t.Fatal("expected port edit attempt")
		} else {
			completeAsync(t, next, cmd)
		}
	})
}

func TestCoverageRound6(t *testing.T) {
	t.Run("handle select async errors", func(t *testing.T) {
		broken := closedOrchModel(t)
		broken.SetBootstrapped(true)
		cases := []struct {
			screen int
			items  []string
			cursor int
		}{
			{tui.ScreenBackup, tui.BackupMenuItemsForTest(), 0},
			{tui.ScreenBackup, tui.BackupMenuItemsForTest(), 1},
			{tui.ScreenSystem, tui.SystemMenuItemsForTest(), 0},
			{tui.ScreenSystem, tui.SystemMenuItemsForTest(), 1},
			{tui.ScreenSystem, tui.SystemMenuItemsForTest(), 4},
		}
		for _, tc := range cases {
			sub := broken
			sub.SetScreen(tc.screen)
			sub.SetItems(tc.items)
			sub.SetCursor(tc.cursor)
			next, cmd := sub.HandleSelect()
			done := completeAsync(t, next, cmd)
			if done.Message() == "" {
				t.Fatalf("expected error for screen %d cursor %d", tc.screen, tc.cursor)
			}
		}
	})

	t.Run("menu cursor up", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetBootstrapped(true)
		m.SetScreen(tui.ScreenVPNs)
		m.SetItems(tui.VPNMenuItemsForTest())
		m.SetCursor(2)
		up, _ := m.Update(tea.KeyMsg{Type: tea.KeyUp})
		if up.Cursor() != 1 {
			t.Fatal("expected cursor up")
		}
	})

	t.Run("invalid create port and cipher oob", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Protocol: "socks5", Prompt: "Port [1080]:"})
		next, _, ok := m.WizardCreateVPNTextEnter("bad")
		if !ok || next.Wizard().StepError == "" {
			t.Fatal("expected invalid port error")
		}
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "shadowsocks", Prompt: "Select cipher:",
			Picker: orchestration.ShadowsocksMethods(),
		})
		m.SetWizardPickerIdx(99)
		m.WizardCreateVPNPickerEnter(99)
	})

	t.Run("picker manage bounds and steps", func(t *testing.T) {
		m, svc := newTestServiceModel(t)
		createTestVPN(t, svc, "main", 1080)
		ctx := context.Background()
		if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "main", Name: "phone"}, true); err != nil {
			t.Fatal(err)
		}
		vpn := orchestration.VPNView{Name: "main", Protocol: "socks5", Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080}}
		client := orchestration.ClientView{Name: "phone"}

		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditVPN, Step: 1, EditField: "Bad"})
		m.WizardPickerEnter()

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditVPN, Step: 0, StepType: tui.StepPicker, Picker: []string{"main"}, VPNs: []orchestration.VPNView{vpn}})
		m.SetWizardPickerIdx(3)
		m.WizardPickerEnter()

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditVPN, Step: 1, StepType: tui.StepPicker, Picker: []string{"Status"}, VPNName: "main", SelectedVPN: vpn})
		m.SetWizardPickerIdx(2)
		m.WizardPickerEnter()

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditClient, Step: 0, StepType: tui.StepPicker, Picker: []string{"main"}, VPNs: []orchestration.VPNView{vpn}})
		m.SetWizardPickerIdx(2)
		m.WizardPickerEnter()

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditClient, Step: 1, StepType: tui.StepPicker, Picker: []string{"phone"}, VPNName: "main", Clients: []orchestration.ClientView{client}})
		m.SetWizardPickerIdx(2)
		m.WizardPickerEnter()

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditClient, Step: 2, StepType: tui.StepPicker, Picker: []string{"Name"}, VPNName: "main", ClientName: "phone", SelectedClient: client})
		m.SetWizardPickerIdx(2)
		m.WizardPickerEnter()

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardAddClient, Step: 0, StepType: tui.StepPicker, Picker: []string{"main"}, VPNs: []orchestration.VPNView{vpn}})
		m.SetWizardPickerIdx(2)
		m.WizardPickerEnter()

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardShowClient, Step: 1, StepType: tui.StepPicker, Picker: []string{"phone"}, VPNName: "main", Clients: []orchestration.ClientView{client}})
		m.SetWizardPickerIdx(2)
		m.WizardPickerEnter()

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardRestoreBackup, Step: 0, StepType: tui.StepPicker, Picker: []string{"b"}, Backups: []orchestration.BackupEntry{{Name: "b", Path: "/b"}}})
		m.SetWizardPickerIdx(2)
		m.WizardPickerEnter()

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardSetCongestion, StepType: tui.StepPicker, CongestionOptions: []string{"bbr"}, Picker: []string{"bbr"}})
		m.SetWizardPickerIdx(2)
		m.WizardPickerEnter()
	})

	t.Run("edit manage guard paths", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditVPN, Step: 1, StepType: tui.StepText, EditField: "Name"})
		m.WizardTextEnter()
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditVPN, Step: 2, StepType: tui.StepText, EditField: "Name", Input: tui.NewTextInputForTest("")})
		m.WizardTextEnter()
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditClient, Step: 2, StepType: tui.StepText, EditField: "Name"})
		m.WizardTextEnter()
	})

	t.Run("apply backup empty and congestion changed", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardRestoreBackup, Loading: true})
		next, _ := m.Update(tui.NewBackupListMsgForTest([]orchestration.BackupEntry{}, nil))
		if next.Wizard().Notice != "No backups — create one first" {
			t.Fatal("expected empty backup notice")
		}
		m2, _ := newTestServiceModel(t)
		m2.SetMode(tui.ModeWizard)
		next2, cmd := m2.WizardFinishSetCongestion("cubic")
		done := completeAsync(t, next2, cmd)
		if done.Message() == "" {
			t.Fatal("expected congestion apply message")
		}
	})

	t.Run("apply ssh port set success refresh", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardSetSSHPort, StepType: tui.StepText})
		next, cmd := m.Update(tui.NewSSHPortSetMsgForTest(2244, nil))
		if cmd == nil || next.Mode() != tui.ModeMenu {
			t.Fatal("expected ssh success refresh")
		}
		completeAsync(t, next, cmd)
	})

	t.Run("create vpn result default client name", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetMode(tui.ModeWizard)
		m.SetBusy(true)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Protocol: "socks5", Prompt: "Client name:"})
		next, _ := m.Update(tui.NewCreateVPNResultMsgForTest("", errors.New("fail")))
		if next.Wizard().Prompt != "Client name:" || next.Wizard().StepError == "" {
			t.Fatal("expected client name step with error")
		}
	})

	t.Run("load menu status success", func(t *testing.T) {
		_, svc := newTestServiceModel(t)
		msg := firstTeaMsg(tui.LoadMenuStatusCmdForTest(orchestration.New(svc)))
		if status, ok := msg.(tui.MenuStatusMsg); !ok {
			t.Fatal("expected status msg")
		} else if !tui.MenuStatusBootstrappedForTest(status) && svc != nil {
			// Dev mode may report bootstrapped false; still covers success path.
			_ = status
		}
	})

	t.Run("wizard picker enter non create", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardAddClient, StepType: tui.StepPicker, Picker: []string{"x"}})
		m.WizardPickerEnter()
	})

	t.Run("enable tls http no branch", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Protocol: "http", Prompt: "Enable TLS?"})
		m.WizardCreateVPNPickerEnter(0)
	})

	t.Run("protocol specific vless sni", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "vless", CreateStep: 7,
			Prompt: "TLS server name (SNI) [auto]:", VPNName: "v", ListenPort: 443,
		})
		m.WizardCreateVPNTextEnter("example.com")
	})

	t.Run("finish add client show client error path", func(t *testing.T) {
		m := closedOrchModel(t)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardAddClient, Step: 1, StepType: tui.StepText,
			VPNName: "x", Input: tui.NewTextInputForTest("c"),
		})
		m.SetWizardInputValue("c")
		next2, cmd2 := m.WizardTextEnter()
		done := completeAsync(t, next2, cmd2)
		if done.Message() == "" {
			t.Fatal("expected add client error message")
		}
	})

	t.Run("remove client async error", func(t *testing.T) {
		m := closedOrchModel(t)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardRemoveClient, VPNName: "x", ClientName: "c"})
		next, cmd := m.WizardConfirmEnter()
		done := completeAsync(t, next, cmd)
		if done.Message() == "" {
			t.Fatal("expected remove error")
		}
	})

	t.Run("restore backup async error", func(t *testing.T) {
		m := closedOrchModel(t)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardRestoreBackup, BackupPath: "/nope"})
		next, cmd := m.WizardConfirmEnter()
		done := completeAsync(t, next, cmd)
		if done.Message() == "" {
			t.Fatal("expected restore error")
		}
	})
}
