package tui_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/ivan-khludov/obscura/internal/config"
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/firewall"
	"github.com/ivan-khludov/obscura/internal/manifest"
	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/runtime"
	"github.com/ivan-khludov/obscura/internal/service"
	"github.com/ivan-khludov/obscura/internal/singboxcheck"
	"github.com/ivan-khludov/obscura/internal/sshd"
	"github.com/ivan-khludov/obscura/internal/store"
	"github.com/ivan-khludov/obscura/internal/sysctl"
	"github.com/ivan-khludov/obscura/internal/systemd"
	"github.com/ivan-khludov/obscura/internal/tui"
)

type noInitialClientProtocol struct{ stubProtocol }

func (noInitialClientProtocol) Type() string                             { return "noclient" }
func (noInitialClientProtocol) NeedsInitialClient(domain.VPNConfig) bool { return false }
func (noInitialClientProtocol) BuildProtocolData(protocol.BuildContext, domain.CreateVPNSpec, string, protocol.BuildMode) ([]byte, error) {
	return []byte("{}"), nil
}

type stubProtocol struct{}

func (stubProtocol) Type() string                                              { return "stub" }
func (stubProtocol) ValidateVPN(domain.VPNConfig, []domain.ClientConfig) error { return nil }
func (stubProtocol) ValidateClient(domain.ClientConfig) error                  { return nil }
func (stubProtocol) RenderInbound(domain.VPNConfig, []domain.ClientConfig) (map[string]any, error) {
	return map[string]any{"type": "direct"}, nil
}
func (stubProtocol) RenderEndpoints(domain.VPNConfig, []domain.ClientConfig) ([]map[string]any, error) {
	return nil, nil
}
func (stubProtocol) AdditionalInbounds(domain.VPNConfig, []domain.ClientConfig) ([]map[string]any, error) {
	return nil, nil
}
func (stubProtocol) ClientURI(domain.VPNConfig, []domain.ClientConfig, domain.ClientConfig, string) (string, error) {
	return "stub://x", nil
}
func (stubProtocol) ClientQRContent(domain.VPNConfig, []domain.ClientConfig, domain.ClientConfig, string) (string, error) {
	return "stub://x", nil
}
func (stubProtocol) DefaultListen() domain.ListenOptions { return domain.DefaultListenOptions() }
func (stubProtocol) SupportedListenFields() []string     { return nil }
func (stubProtocol) RouteExtensions(domain.VPNConfig) ([]map[string]any, error) {
	return nil, nil
}
func (stubProtocol) UsesInbound() bool        { return true }
func (stubProtocol) FirewallProtos() []string { return []string{"tcp"} }

func customRegistry(t *testing.T, protos ...protocol.Protocol) *protocol.Registry {
	t.Helper()
	reg := protocol.NewRegistry()
	for _, p := range protos {
		reg.Register(p)
	}
	return reg
}

func TestCoverageRound7(t *testing.T) {
	t.Run("export and runtime helpers", func(t *testing.T) {
		if err := tui.SSHPortSetErrorForTest(tui.NewSSHPortSetMsgForTest(22, errors.New("x"))); err == nil {
			t.Fatal("expected ssh port error")
		}
		f, err := os.CreateTemp("", "notty-*")
		if err != nil {
			t.Fatal(err)
		}
		path := f.Name()
		_ = f.Close()
		_ = os.Remove(path)
		if tui.IsTTYForTest(f) {
			t.Fatal("expected false for removed file stat error")
		}
		if tui.NewProgramRunnerForTest(tui.NewModelForTest(nil, nil)) == nil {
			t.Fatal("expected default program runner")
		}
		if tui.ProtocolHintForTest("unknown-proto") == "" {
			t.Fatal("expected default protocol hint")
		}
	})

	t.Run("loader success and error paths", func(t *testing.T) {
		m, svc := newTestServiceModel(t)
		createTestVPN(t, svc, "main", 1080)
		orch := orchestration.New(svc)
		if msg := firstTeaMsg(tui.LoadClientsCmdForTest(orch, "main")); msg == nil {
			t.Fatal("expected client list msg")
		}
		_ = m

		svc.SetBackupGlobForTest(func(string) ([]string, error) {
			return nil, fmt.Errorf("glob failed")
		})
		if msg := firstTeaMsg(tui.LoadBackupsCmdForTest(orch)); msg == nil {
			t.Fatal("expected backup error msg")
		}
	})

	t.Run("create vpn cmd without client uri", func(t *testing.T) {
		dir := t.TempDir()
		app := &config.App{
			DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
			ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
			DevMode: true,
		}
		st, err := store.Open(app.DBPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		man := manifest.NewManager(app.ManifestPath)
		_ = man.Load()
		reg := customRegistry(t, noInitialClientProtocol{})
		svc := service.NewService(app, st, reg, man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
		orch := orchestration.New(svc)
		req := tui.BuildCreateVPNRequestForTest(tui.WizardStateForTest{
			VPNName: "nc", Protocol: "noclient", ListenPort: 12010,
		})
		msg := firstTeaMsg(tui.CreateVPNCmdForTest(orch, req))
		result, ok := msg.(tui.CreateVPNResultMsg)
		if !ok || tui.CreateVPNResultErrorForTest(result) != nil {
			t.Fatalf("expected success without uri, got %#v", msg)
		}
	})

	t.Run("menu backup async success", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetBootstrapped(true)
		m.SetScreen(tui.ScreenBackup)
		m.SetItems(tui.BackupMenuItemsForTest())

		m.SetCursor(0)
		next, cmd := m.HandleSelect()
		done := completeAsync(t, next, cmd)
		if done.Message() == "" {
			t.Fatal("expected create backup message")
		}

		m.SetCursor(1)
		next2, cmd2 := m.HandleSelect()
		done2 := completeAsync(t, next2, cmd2)
		if done2.Message() == "" {
			t.Fatal("expected list backups message")
		}
	})

	t.Run("update ssh port and congestion in wizard", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetMode(tui.ModeMenu)
		next, _ := m.Update(tui.NewSSHPortSetMsgForTest(2222, nil))
		if next.Mode() != tui.ModeMenu {
			t.Fatal("expected menu mode for ssh port outside wizard")
		}

		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardSetCongestion, StepType: tui.StepPicker,
			CongestionOptions: []string{"bbr", "cubic"}, CongestionCurrent: "bbr",
		})
		m.SetWizardPickerIdx(0)
		next2, _ := m.WizardPickerEnter()
		if next2.Wizard().Notice != "bbr is already active" {
			t.Fatalf("expected unchanged congestion notice, got %q", next2.Wizard().Notice)
		}

		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardSetCongestion, StepType: tui.StepPicker})
		next3, _ := m.Update(tui.NewCongestionListMsgForTest([]string{"bbr"}, "bbr", nil))
		next3.SetWizardPickerIdx(0)
		if _, cmd := next3.WizardPickerEnter(); cmd != nil {
			t.Fatal("expected no cmd when congestion unchanged")
		}
	})

	t.Run("wizard fallthrough and bounds", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardAddClient, StepType: tui.StepPicker, Picker: []string{"x"}})
		if _, cmd := m.WizardPickerEnter(); cmd != nil {
			t.Fatal("expected nil cmd for unhandled manage picker")
		}
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardAddClient, StepType: tui.StepText, Prompt: "unknown"})
		if _, cmd := m.WizardTextEnter(); cmd != nil {
			t.Fatal("expected nil cmd for unhandled manage text")
		}
	})

	t.Run("create dispatch defaults and infer steps", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Prompt: "Unknown step"})
		if _, _, ok := m.WizardCreateVPNPickerEnter(0); ok {
			t.Fatal("expected false for unknown picker step")
		}
		if _, _, ok := m.WizardCreateVPNTextEnter("x"); ok {
			t.Fatal("expected false for unknown text step")
		}
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "socks5", Prompt: "Enable TLS?",
		})
		if _, _, ok := m.WizardCreateVPNPickerEnter(0); ok {
			t.Fatal("expected false for enable tls on socks5")
		}
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "socks5", Prompt: "TLS mode:",
		})
		if _, _, ok := m.WizardCreateVPNPickerEnter(0); ok {
			t.Fatal("expected false for tls mode on socks5")
		}
		if step := tui.InferCreateStepFromPromptForTest(tui.WizardStateForTest{Prompt: "Masquerade file directory [/var/www]:"}); step == 0 {
			t.Fatal("expected masquerade file step")
		}
	})

	t.Run("protocol validation failures with orch", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetMode(tui.ModeWizard)

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "vless", VPNName: "vl", ListenPort: 443,
			VlessFlow: orchestration.VLESSFlowVision(), Prompt: "Transport options:",
			Picker: orchestration.InboundTransportModes("vless"),
		})
		for i, mode := range orchestration.InboundTransportModes("vless") {
			if mode == "gRPC" {
				m.SetWizardPickerIdx(i)
				next, _, ok := m.WizardCreateVPNPickerEnter(i)
				if !ok || next.Wizard().StepError == "" {
					t.Fatal("expected vision+grpc validation error")
				}
			}
		}

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", VPNName: "hy", ListenPort: 443,
			Hy2ServerName: "example.com", Hy2UpMbps: 100, Hy2DownMbps: 100, Hy2IgnoreBW: true,
			Hy2PendingPrompt: "down_mbps", Prompt: "Download bandwidth (Mbps) [100]:",
			Input: tui.NewTextInputForTest("100"),
		})
		m.SetWizardInputValue("100")
		next, _, ok := m.WizardCreateVPNTextEnter("100")
		if !ok || next.Wizard().StepError == "" {
			t.Fatal("expected hy2 bandwidth conflict")
		}

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "shadowsocks", VPNName: "ss", ListenPort: 8388,
			SSMethod: "aes-128-gcm", Prompt: "Transport options:",
			Picker: orchestration.ShadowsocksTransportModes(),
		})
		for i, mode := range orchestration.ShadowsocksTransportModes() {
			if mode == "ShadowTLS" {
				continue
			}
			m.SetWizard(tui.WizardStateForTest{
				Kind: tui.WizardCreateVPN, Protocol: "shadowsocks", VPNName: "ss", ListenPort: 8388,
				SSMethod: "aes-128-gcm", SSTransport: mode, Prompt: "Transport options:",
				Picker: orchestration.ShadowsocksTransportModes(),
			})
			m.SetWizardPickerIdx(i)
			m.WizardCreateVPNPickerEnter(i)
		}
	})

	t.Run("inbound flow branches", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetMode(tui.ModeWizard)

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "vless", Prompt: "VLESS flow:",
			Picker: orchestration.VLESSFlowModes(),
		})
		m.WizardCreateVPNPickerEnter(99)

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "vless", Prompt: "uTLS fingerprint:",
			Picker: []string{"Chrome"},
		})
		m.WizardCreateVPNPickerEnter(99)

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "vless", VPNName: "vl", ListenPort: 443,
			VlessFlow: orchestration.VLESSFlowVision(), TrojanTransport: "grpc",
			TrojanPendingPrompt: "path", Prompt: "Transport path:", Input: tui.NewTextInputForTest("/"),
		})
		m.SetWizardInputValue("/")
		next, _, ok := m.WizardCreateVPNTextEnter("/")
		if !ok || next.Wizard().StepError == "" {
			t.Fatal("expected transport detail validation error")
		}

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "trojan", VPNName: "tr", ListenPort: 443,
			Prompt: "TLS server name (SNI) [auto]:", Input: tui.NewTextInputForTest(""),
		})
		m.SetWizardInputValue("")
		if _, _, ok := m.WizardCreateVPNTextEnter(""); !ok {
			t.Fatal("expected trojan sni accept")
		}

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", VPNName: "hy", ListenPort: 443,
			Prompt: "TLS server name (SNI) [auto]:", Input: tui.NewTextInputForTest("example.com"),
		})
		if _, _, ok := m.WizardCreateVPNTextEnter("example.com"); !ok {
			t.Fatal("expected hy2 sni")
		}

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "tuic", VPNName: "tu", ListenPort: 443,
			Prompt: "TLS server name (SNI) [auto]:", Input: tui.NewTextInputForTest("example.com"),
		})
		if _, _, ok := m.WizardCreateVPNTextEnter("example.com"); !ok {
			t.Fatal("expected tuic sni")
		}

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "trojan", TrojanPendingPrompt: "other",
			Prompt: "Transport option:", Input: tui.NewTextInputForTest("x"),
		})
		m.WizardCreateVPNTextEnter("x")

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "trojan", TrojanTransport: "ws",
			TrojanPendingPrompt: "path", Prompt: "Transport path:", Input: tui.NewTextInputForTest(""),
		})
		m.WizardCreateVPNTextEnter("")

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "trojan", Prompt: "Fallback port [0=disabled]:",
			Input: tui.NewTextInputForTest("bad"),
		})
		m.WizardCreateVPNTextEnter("bad")
	})

	t.Run("hy2 detail branches", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", Prompt: "Bandwidth:",
			Picker: []string{"No limit", "Set bandwidth", "Ignore client bandwidth (BBR)"},
		})
		m.WizardCreateVPNPickerEnter(99)

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", Prompt: "Obfuscation:",
			Picker: []string{"None", "Salamander"},
		})
		m.WizardCreateVPNPickerEnter(99)

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", Prompt: "Masquerade:",
			Picker: []string{"None", "Proxy", "File"},
		})
		m.WizardCreateVPNPickerEnter(99)

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", Hy2PendingPrompt: "masquerade_proxy",
			Prompt: "Masquerade proxy URL [http://127.0.0.1:8080]:", Input: tui.NewTextInputForTest(""),
		})
		m.WizardCreateVPNTextEnter("")

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", Hy2PendingPrompt: "masquerade_file",
			Prompt: "Masquerade file directory [/var/www]:", Input: tui.NewTextInputForTest(""),
		})
		m.WizardCreateVPNTextEnter("")

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", Hy2PendingPrompt: "up_mbps",
			Prompt: "Upload bandwidth (Mbps) [100]:", Input: tui.NewTextInputForTest("bad"),
		})
		m.WizardCreateVPNTextEnter("bad")

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", Hy2PendingPrompt: "down_mbps", Hy2UpMbps: 100,
			Prompt: "Download bandwidth (Mbps) [100]:", Input: tui.NewTextInputForTest("bad"),
		})
		m.WizardCreateVPNTextEnter("bad")

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", Hy2PendingPrompt: "other",
			Prompt: "Download bandwidth (Mbps) [100]:",
		})
		m.WizardCreateVPNTextEnter("100")
	})

	t.Run("wireguard and ss transport", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetMode(tui.ModeWizard)

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "wireguard", Prompt: "Subnet [10.8.0.1/24]:",
			Input: tui.NewTextInputForTest("bad"),
		})
		m.WizardCreateVPNTextEnter("bad")

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "wireguard", VPNName: "wg", ListenPort: 51820,
			WGAddress: "10.8.0.1/24", Prompt: "MTU [1420]:", Input: tui.NewTextInputForTest("bad"),
		})
		m.WizardCreateVPNTextEnter("bad")

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "shadowsocks", Prompt: "Transport options:",
			Picker: orchestration.ShadowsocksTransportModes(),
		})
		m.WizardCreateVPNPickerEnter(99)

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "shadowsocks", VPNName: "ss", ListenPort: 8388,
			SSMethod: "aes-128-gcm", Prompt: "Transport options:",
			Picker: orchestration.ShadowsocksTransportModes(),
		})
		if _, cmd := m.WizardAcceptSSTransport(0); cmd != nil {
			_ = cmd
		}
	})

	t.Run("inbound transport modes", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "vless", VPNName: "vl", ListenPort: 443,
			Prompt: "Transport options:", Picker: orchestration.InboundTransportModes("vless"),
		})
		for i, mode := range orchestration.InboundTransportModes("vless") {
			m.SetWizard(tui.WizardStateForTest{
				Kind: tui.WizardCreateVPN, Protocol: "vless", VPNName: "vl", ListenPort: 443,
				Prompt: "Transport options:", Picker: orchestration.InboundTransportModes("vless"),
			})
			m.SetWizardPickerIdx(i)
			m.WizardCreateVPNPickerEnter(i)
			_ = mode
		}
	})

	t.Run("manage wizard branches", func(t *testing.T) {
		m, svc := newTestServiceModel(t)
		createTestVPN(t, svc, "main", 1080)
		ctx := context.Background()
		if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "main", Name: "phone"}, true); err != nil {
			t.Fatal(err)
		}
		vpn := orchestration.VPNView{Name: "main", Protocol: "socks5", Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080}}
		client := orchestration.ClientView{Name: "phone"}

		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditClient, Step: 3, EditField: "Bad"})
		m.WizardTextEnter()

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditClient, Step: 3, EditField: "Name", VPNName: "main", ClientName: "phone", Input: tui.NewTextInputForTest("")})
		m.WizardTextEnter()

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditVPN, Step: 2, EditField: "Bad"})
		m.WizardTextEnter()

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardAddClient, Step: 1, StepType: tui.StepText, Prompt: "Client name:", Input: tui.NewTextInputForTest("")})
		m.WizardTextEnter()

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditClient, Step: 0, StepType: tui.StepPicker, Picker: []string{"main"}, VPNs: []orchestration.VPNView{vpn}})
		m.SetWizardPickerIdx(0)
		m.WizardPickerEnter()

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditClient, Step: 1, StepType: tui.StepPicker, Picker: []string{"phone"}, Clients: []orchestration.ClientView{client}, VPNName: "main"})
		m.SetWizardPickerIdx(0)
		m.WizardPickerEnter()

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditClient, Step: 2, StepType: tui.StepPicker, Picker: []string{"Name"}, VPNName: "main", ClientName: "phone", SelectedClient: client})
		m.SetWizardPickerIdx(0)
		m.WizardPickerEnter()

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditClient, Step: 3, StepType: tui.StepPicker, EditField: "Name", VPNName: "main", ClientName: "phone"})
		m.WizardPickerEnter()

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditVPN, Step: 2, StepType: tui.StepPicker, EditField: "Status", VPNName: "main", SelectedVPN: vpn, Picker: []string{"Active", "Inactive"}})
		m.WizardPickerEnter()

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardShowClient, Step: 1, ClientName: "phone", VPNName: "main"})
		m.WizardAfterClientPick()

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardAddClient, Step: 0, VPNName: "main"})
		m.WizardAfterVPNPick()
	})

	t.Run("wizard nav render update", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardAddClient, StepType: tui.StepNotice, Notice: "done"})
		next, _ := m.Update(tui.NewVPNListMsgForTest(nil, errors.New("vpns")))
		if next.Wizard().Notice != "vpns" {
			t.Fatal("expected notice step change")
		}

		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, StepType: tui.StepPicker, Picker: []string{"a"}})
		next2, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
		if next2.Mode() != tui.ModeMenu {
			t.Fatal("expected cancel from picker esc")
		}

		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardDeleteVPN, StepType: tui.StepConfirm, Prompt: "Delete?"})
		next3, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
		if cmd == nil {
			t.Fatal("expected confirm cmd")
		}
		_ = next3

		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardSetSSHPort, StepType: tui.StepText})
		next4, _ := m.Update(tui.NewSSHPortSetMsgForTest(2244, nil))
		if next4.Mode() != tui.ModeMenu {
			t.Fatal("expected menu after ssh set in wizard update")
		}

		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, StepType: tui.StepText, Prompt: "VPN name:", Input: tui.NewTextInputForTest("")})
		m.SetWizardInputValue("")
		next5, _ := m.WizardTextEnter()
		if next5.Wizard().VPNName != "" {
			t.Fatal("expected empty vpn name ignored at step 0")
		}

		m.SetQuitting(false)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, StepType: tui.StepNotice, Notice: "x"})
		m.SetBusy(false)
		out := m.View()
		if out == "" {
			t.Fatal("expected wizard notice view")
		}

		m2 := tui.NewModelForTest(nil, nil)
		m2.SetMode(tui.ModeWizard)
		m2.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, StepType: tui.StepText, Prompt: "VPN name:"})
		if m2.View() == "" {
			t.Fatal("expected wizard text view")
		}

		m2.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, WizardHistory: []tui.WizardStateForTest{{Prompt: "prev", StepType: tui.StepText}}})
		if _, cmd := m2.WizardCreateVPNBack(); cmd == nil {
			t.Fatal("expected back with history")
		}
	})

	t.Run("ssh port success production mode", func(t *testing.T) {
		dir := t.TempDir()
		app := &config.App{
			DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
			ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
		}
		st, err := store.Open(app.DBPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		man := manifest.NewManager(app.ManifestPath)
		_ = man.Load()
		man.SetSSHPort(22)
		svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
		svc.SetRootCheckForTest(func() bool { return true })
		cfgPath := filepath.Join(dir, "sshd_config")
		if err := os.WriteFile(cfgPath, []byte("Port 22\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg := &sshd.Config{ReadFile: os.ReadFile, WriteFile: os.WriteFile}
		run := &sshd.Runner{RunCommand: func(context.Context, string, ...string) ([]byte, error) { return nil, nil }}
		svc.SetSSHDForTest(cfgPath, cfg, run)
		m := tui.NewModelForTest(app, orchestration.New(svc))
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardSetSSHPort, StepType: tui.StepText, Input: tui.NewTextInputForTest("2222")})
		m.SetWizardInputValue("2222")
		next, cmd := m.WizardAcceptSSHPort("2222")
		msg := firstTeaMsg(cmd)
		if _, ok := msg.(tui.SSHPortSetMsg); !ok {
			t.Fatalf("expected ssh port set msg, got %#v cmd=%v next=%v", msg, cmd, next)
		}
	})

	t.Run("busy non ctrl c ignored", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetBusy(true)
		next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
		if cmd != nil || next.Busy() != true {
			t.Fatal("expected busy to swallow keys")
		}
	})

	t.Run("congestion finish error", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetMode(tui.ModeWizard)
		next, cmd := m.WizardFinishSetCongestion("cubic")
		done := completeAsync(t, next, cmd)
		if done.Message() == "" {
			t.Fatal("expected congestion error in dev mode")
		}
	})

	t.Run("add client show client fallback", func(t *testing.T) {
		m := closedOrchModel(t)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardAddClient, VPNName: "main", StepType: tui.StepText,
			Prompt: "Client name:", Input: tui.NewTextInputForTest("phone"),
		})
		m.SetWizardInputValue("phone")
		next, cmd := m.WizardTextEnter()
		done := completeAsync(t, next, cmd)
		if done.Message() == "" {
			t.Fatal("expected add client error")
		}
	})
}

func TestCoverageRound8(t *testing.T) {
	t.Run("is tty regular file", func(t *testing.T) {
		restore := tui.SetIsTTYForTest(func(f *os.File) bool {
			info, err := f.Stat()
			if err != nil {
				return false
			}
			return (info.Mode() & os.ModeCharDevice) != 0
		})
		defer restore()
		f, err := os.CreateTemp(t.TempDir(), "regular-*")
		if err != nil {
			t.Fatal(err)
		}
		if tui.IsTTYForTest(f) {
			t.Fatal("expected regular file is not tty")
		}
		_ = f.Close()
	})

	t.Run("menu backup and doctor success", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetBootstrapped(true)
		m.SetScreen(tui.ScreenBackup)
		m.SetItems(tui.BackupMenuItemsForTest())
		m.SetCursor(0)
		next, cmd := m.HandleSelect()
		done := completeAsync(t, next, cmd)
		if !strings.HasPrefix(done.Message(), "New backup:") {
			t.Fatalf("expected backup success, got %q", done.Message())
		}
		m.SetCursor(1)
		next2, cmd2 := m.HandleSelect()
		done2 := completeAsync(t, next2, cmd2)
		if done2.Message() == "" || done2.Message() == "No backups" {
			// List may be empty label but still success path.
			if done2.Message() == "" {
				t.Fatalf("expected list backups message, got %q", done2.Message())
			}
		}

		m.SetScreen(tui.ScreenSystem)
		m.SetItems(tui.SystemMenuItemsForTest())
		m.SetCursor(1)
		next3, cmd3 := m.HandleSelect()
		done3 := completeAsync(t, next3, cmd3)
		if done3.Message() == "" {
			t.Fatal("expected doctor message")
		}
	})

	t.Run("doctor error closed store", func(t *testing.T) {
		broken := closedOrchModel(t)
		broken.SetBootstrapped(true)
		broken.SetScreen(tui.ScreenSystem)
		broken.SetItems(tui.SystemMenuItemsForTest())
		broken.SetCursor(1)
		next, cmd := broken.HandleSelect()
		done := completeAsync(t, next, cmd)
		if done.Message() == "" {
			t.Fatal("expected doctor error")
		}
	})

	t.Run("congestion apply success production", func(t *testing.T) {
		dir := t.TempDir()
		app := &config.App{
			DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
			ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
			DevMode: false,
		}
		st, err := store.Open(app.DBPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		man := manifest.NewManager(app.ManifestPath)
		_ = man.Load()
		svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
		svc.SetRootCheckForTest(func() bool { return true })
		svc.SetCongestionListerForTest(func() ([]string, error) { return []string{"bbr", "cubic"}, nil })
		svc.SetSysctlForTest(&sysctl.Manager{
			ConfPath: filepath.Join(dir, "sysctl.conf"),
			Reload:   func() error { return nil },
		})
		m := tui.NewModelForTest(app, orchestration.New(svc))
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardSetCongestion, StepType: tui.StepPicker,
			CongestionOptions: []string{"bbr", "cubic"}, CongestionCurrent: "cubic",
		})
		m.SetWizardPickerIdx(0)
		next, cmd := m.WizardPickerEnter()
		done := completeAsync(t, next, cmd)
		if !strings.Contains(done.Message(), "bbr") {
			t.Fatalf("expected congestion apply success, got %q", done.Message())
		}
	})

	t.Run("wizard picker text fallthrough", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardSetSSHPort, StepType: tui.StepPicker, Picker: []string{"x"}})
		if _, cmd := m.WizardPickerEnter(); cmd != nil {
			t.Fatal("expected nil for unhandled wizard kind in picker")
		}
	})

	t.Run("create vpn text shadowtls default handshake", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "shadowsocks",
			Prompt: "ShadowTLS handshake server [auto]:", Input: tui.NewTextInputForTest(""),
		})
		if _, _, ok := m.WizardCreateVPNTextEnter(""); !ok {
			t.Fatal("expected shadowtls default handshake")
		}
	})

	t.Run("sni validation failures cross protocol", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetMode(tui.ModeWizard)
		for _, proto := range []string{"hysteria2", "tuic"} {
			m.SetWizard(tui.WizardStateForTest{
				Kind: tui.WizardCreateVPN, Protocol: proto, VPNName: "x", ListenPort: 443,
				VlessFlow: orchestration.VLESSFlowVision(), TrojanTransport: "grpc",
				Prompt: "TLS server name (SNI) [auto]:", Input: tui.NewTextInputForTest("example.com"),
			})
			next, _, ok := m.WizardCreateVPNTextEnter("example.com")
			if !ok || next.Wizard().StepError == "" {
				t.Fatalf("expected %s sni validation error", proto)
			}
		}
	})

	t.Run("vless flow validation failure", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "vless", VPNName: "vl", ListenPort: 443,
			VlessFlow: orchestration.VLESSFlowVision(), TrojanTransport: "grpc",
			TrojanTransportPath: "/", Prompt: "VLESS flow:", Picker: orchestration.VLESSFlowModes(),
		})
		m.SetWizardPickerIdx(1)
		next, _, ok := m.WizardCreateVPNPickerEnter(1)
		if !ok || next.Wizard().StepError == "" {
			t.Fatal("expected vless flow validation error")
		}
	})

	t.Run("inbound transport validation all modes", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetMode(tui.ModeWizard)
		modes := orchestration.InboundTransportModes("vless")
		for i, mode := range modes {
			if mode != "gRPC" {
				continue
			}
			m.SetWizard(tui.WizardStateForTest{
				Kind: tui.WizardCreateVPN, Protocol: "vless", VPNName: "vl", ListenPort: 443,
				VlessFlow: orchestration.VLESSFlowVision(), Prompt: "Transport options:", Picker: modes,
			})
			m.SetWizardPickerIdx(i)
			next, _, ok := m.WizardCreateVPNPickerEnter(i)
			if !ok || next.Wizard().StepError == "" {
				t.Fatal("expected validation error for vision+grpc transport")
			}
		}
	})

	t.Run("trojan transport detail and fallback validation", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "vless", VPNName: "vl", ListenPort: 443,
			VlessFlow: orchestration.VLESSFlowVision(), TrojanTransport: "grpc",
			TrojanPendingPrompt: "service_name", Prompt: "gRPC service name:", Input: tui.NewTextInputForTest("svc"),
		})
		m.WizardCreateVPNTextEnter("svc")

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "trojan", VPNName: "tr", ListenPort: 443,
			TrojanServerName: "example.com", TrojanTransport: "ws", TrojanPendingPrompt: "host",
			Prompt: "Transport host:", Input: tui.NewTextInputForTest("host.example.com"),
		})
		m.WizardCreateVPNTextEnter("host.example.com")

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "trojan", VPNName: "tr", ListenPort: 443,
			TrojanServerName: "example.com", Prompt: "Fallback port [0=disabled]:", Input: tui.NewTextInputForTest("99999"),
		})
		m.WizardCreateVPNTextEnter("99999")
	})

	t.Run("hy2 masquerade and bandwidth validation", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", VPNName: "hy", ListenPort: 443,
			Hy2ServerName: "example.com", Prompt: "Masquerade:", Picker: []string{"None", "Proxy", "File"},
		})
		m.SetWizardPickerIdx(1)
		m.WizardCreateVPNPickerEnter(1)

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", VPNName: "hy", ListenPort: 443,
			Hy2ServerName: "example.com", Hy2PendingPrompt: "masquerade_proxy",
			Prompt: "Masquerade proxy URL [http://127.0.0.1:8080]:", Input: tui.NewTextInputForTest("not-a-url"),
		})
		m.WizardCreateVPNTextEnter("not-a-url")

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", VPNName: "hy", ListenPort: 443,
			Hy2ServerName: "example.com", Hy2UpMbps: 50, Hy2PendingPrompt: "down_mbps",
			Prompt: "Download bandwidth (Mbps) [50]:", Input: tui.NewTextInputForTest("0"),
		})
		m.WizardCreateVPNTextEnter("0")
	})

	t.Run("wireguard subnet mtu validation", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "wireguard", VPNName: "wg", ListenPort: 51820,
			Prompt: "Subnet [10.8.0.1/24]:", Input: tui.NewTextInputForTest("not-a-subnet"),
		})
		next, _, ok := m.WizardCreateVPNTextEnter("not-a-subnet")
		if !ok || !strings.Contains(next.Wizard().Prompt, "invalid") {
			t.Fatal("expected wireguard subnet error")
		}
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "wireguard", VPNName: "wg", ListenPort: 51820,
			WGAddress: "10.8.0.1/24", Prompt: "MTU [1420, empty=default]:", Input: tui.NewTextInputForTest("1000"),
		})
		next2, _, ok := m.WizardCreateVPNTextEnter("1000")
		if !ok || !strings.Contains(next2.Wizard().Prompt, "invalid") {
			t.Fatal("expected wireguard mtu error")
		}
	})

	t.Run("shadowsocks shadowtls path", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "shadowsocks", VPNName: "ss", ListenPort: 8388,
			SSMethod: "aes-128-gcm", Prompt: "Transport options:", Picker: orchestration.ShadowsocksTransportModes(),
		})
		for i, mode := range orchestration.ShadowsocksTransportModes() {
			if mode != "ShadowTLS" {
				continue
			}
			m.SetWizardPickerIdx(i)
			if _, _, ok := m.WizardCreateVPNPickerEnter(i); !ok {
				t.Fatal("expected shadowtls branch")
			}
		}
	})

	t.Run("manage edit flows success", func(t *testing.T) {
		m, svc := newTestServiceModel(t)
		createTestVPN(t, svc, "web", 8080)
		ctx := context.Background()
		if _, _, err := svc.AddClient(ctx, service.AddClientInput{VPNName: "web", Name: "phone"}, true); err != nil {
			t.Fatal(err)
		}
		vpn := orchestration.VPNView{Name: "web", Protocol: "http", Enabled: true, Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8080}}
		client := orchestration.ClientView{Name: "phone", Enabled: true}

		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditVPN, Step: 2, EditField: "Client host", VPNName: "web", SelectedVPN: vpn})
		if _, cmd := m.WizardShowEditVPNValue(); cmd == nil {
			t.Fatal("expected client host edit blink")
		}

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditVPN, Step: 2, EditField: "Status", VPNName: "web", SelectedVPN: vpn, Picker: []string{"Active", "Inactive"}})
		next, cmd := m.WizardPickerEnter()
		completeAsync(t, next, cmd)

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditClient, Step: 2, EditField: "Password", VPNName: "web", ClientName: "phone", SelectedClient: client})
		if _, cmd := m.WizardShowEditClientValue(); cmd == nil {
			t.Fatal("expected password edit blink")
		}

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditClient, Step: 3, EditField: "Status", VPNName: "web", ClientName: "phone", SelectedClient: client, Picker: []string{"Active", "Inactive"}})
		next2, cmd2 := m.WizardPickerEnter()
		completeAsync(t, next2, cmd2)

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditClient, Step: 3, EditField: "Name", VPNName: "web", ClientName: "phone", Input: tui.NewTextInputForTest("phone2")})
		m.SetWizardInputValue("phone2")
		next3, cmd3 := m.WizardTextEnter()
		completeAsync(t, next3, cmd3)

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardAddClient, VPNName: "web", ClientName: "tab", StepType: tui.StepText, Prompt: "Client name:", Input: tui.NewTextInputForTest("tab")})
		m.SetWizardInputValue("tab")
		next4, cmd4 := m.WizardTextEnter()
		completeAsync(t, next4, cmd4)

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardRemoveClient, Step: 1, ClientName: "phone", VPNName: "web"})
		m.WizardAfterClientPick()
	})

	t.Run("wizard nav notice and pop empty", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, StepType: tui.StepNotice, Notice: "loading"})
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Step: 1, StepType: tui.StepNotice, Notice: "done",
			ProtocolOptions: []string{"socks5"}, Loading: false,
		})
		next, _ := m.Update(tui.NewProtocolListMsgForTest([]string{"socks5"}, nil))
		if next.Wizard().Notice == "loading" {
			t.Fatal("expected notice change")
		}
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, WizardHistory: nil})
		if _, cmd := m.WizardCreateVPNBack(); cmd != nil {
			t.Fatal("expected nil pop on empty history")
		}
	})

	t.Run("wizard render branches", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, StepType: tui.StepConfirm, Prompt: "Confirm?"})
		if !strings.Contains(m.View(), "Confirm?") {
			t.Fatal("expected confirm in view")
		}
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, StepType: tui.StepNotice, Notice: ""})
		m.SetBusy(false)
		m.SetMessage("")
		if m.View() == "" {
			t.Fatal("expected empty notice view")
		}
	})

	t.Run("wizard update ssh port in wizard", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardSetSSHPort})
		next, _ := m.Update(tui.NewSSHPortSetMsgForTest(22, errors.New("fail")))
		if !strings.Contains(next.Wizard().Prompt, "try again") {
			t.Fatal("expected ssh port set handling in updateWizard")
		}
	})

	t.Run("create protocol picker oob", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, StepType: tui.StepPicker,
			Prompt: "Select protocol:", ProtocolOptions: []string{"socks5"},
		})
		m.WizardCreateVPNPickerEnter(5)
	})

	t.Run("port subnet mtu fallthrough", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Protocol: "socks5", Prompt: "Unknown port prompt:"})
		if _, _, ok := m.WizardCreateVPNTextEnter("1"); ok {
			t.Fatal("expected false for unknown port prompt")
		}
	})

	t.Run("picker enter create fallthrough", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, StepType: tui.StepPicker, Prompt: "Unknown"})
		if _, cmd := m.WizardPickerEnter(); cmd != nil {
			t.Fatal("expected nil when create picker not handled")
		}
	})

	t.Run("text enter create advance without step change", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Step: 0, Prompt: "VPN name:", Input: tui.NewTextInputForTest("")})
		m.SetWizardInputValue("")
		if _, cmd := m.WizardTextEnter(); cmd != nil {
			t.Fatal("expected no cmd for empty vpn name")
		}
	})

	t.Run("manage picker oob and fallthrough", func(t *testing.T) {
		m, svc := newTestServiceModel(t)
		createTestVPN(t, svc, "main", 1080)
		vpn := orchestration.VPNView{Name: "main", Protocol: "socks5", Listen: domain.ListenOptions{ListenPort: 1080}}
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardDeleteVPN, Step: 0, VPNs: []orchestration.VPNView{vpn}})
		m.SetWizardPickerIdx(5)
		m.WizardPickerEnter()

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditVPN, Step: 3})
		m.WizardPickerEnter()

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditClient, Step: 4, VPNName: "main"})
		m.WizardPickerEnter()
	})
}

func TestCoverageRound9(t *testing.T) {
	t.Run("menu async error paths", func(t *testing.T) {
		dir := t.TempDir()
		blocker := filepath.Join(dir, "block")
		if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		app := &config.App{
			DataDir: filepath.Join(blocker, "data"), DBPath: filepath.Join(dir, "state.db"),
			ConfigPath: filepath.Join(dir, "c.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
			DevMode: true,
		}
		st, err := store.Open(app.DBPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		man := manifest.NewManager(app.ManifestPath)
		_ = man.Load()
		svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
		svc.SetBackupGlobForTest(func(string) ([]string, error) {
			return nil, fmt.Errorf("glob failed")
		})
		m := tui.NewModelForTest(app, orchestration.New(svc))
		m.SetBootstrapped(true)
		m.SetScreen(tui.ScreenBackup)
		m.SetItems(tui.BackupMenuItemsForTest())
		m.SetCursor(0)
		next, cmd := m.HandleSelect()
		if done := completeAsync(t, next, cmd); done.Message() == "" {
			t.Fatal("expected create backup error")
		}
		m.SetCursor(1)
		next2, cmd2 := m.HandleSelect()
		if done2 := completeAsync(t, next2, cmd2); done2.Message() == "" {
			t.Fatal("expected list backup error")
		}
	})

	t.Run("default is tty fn", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "n")
		if err != nil {
			t.Fatal(err)
		}
		if tui.DefaultIsTTYForTest(f) {
			t.Fatal("expected regular file is not tty")
		}
		_ = f.Close()
		_ = tui.ResetIsTTYForTest()
	})

	t.Run("congestion changed async message", func(t *testing.T) {
		dir := t.TempDir()
		app := &config.App{
			DataDir: dir, DBPath: filepath.Join(dir, "state.db"),
			ConfigPath: filepath.Join(dir, "sing-box.json"), ManifestPath: filepath.Join(dir, "manifest.json"),
			DevMode: false,
		}
		st, err := store.Open(app.DBPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		man := manifest.NewManager(app.ManifestPath)
		_ = man.Load()
		svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
		svc.SetRootCheckForTest(func() bool { return true })
		svc.SetCongestionListerForTest(func() ([]string, error) { return []string{"bbr", "cubic"}, nil })
		svc.SetSysctlForTest(&sysctl.Manager{ConfPath: filepath.Join(dir, "sysctl.conf"), Reload: func() error { return nil }})
		m := tui.NewModelForTest(app, orchestration.New(svc))
		next, cmd := m.WizardFinishSetCongestion("cubic")
		done := completeAsync(t, next, cmd)
		if !strings.Contains(done.Message(), "TCP congestion control set to cubic") {
			t.Fatalf("expected changed congestion message, got %q", done.Message())
		}
	})

	t.Run("transport validation each mode vision", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		modes := orchestration.InboundTransportModes("vless")
		for i, mode := range modes {
			if mode == "Direct" {
				continue
			}
			m.SetMode(tui.ModeWizard)
			m.SetWizard(tui.WizardStateForTest{
				Kind: tui.WizardCreateVPN, Protocol: "vless", VPNName: "vl", ListenPort: 443,
				VlessFlow: orchestration.VLESSFlowVision(), HTTPTLS: true,
				Prompt: "Transport options:", Picker: modes,
			})
			m.SetWizardPickerIdx(i)
			m.WizardCreateVPNPickerEnter(i)
		}
	})

	t.Run("hy2 masquerade and bandwidth validate fail", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", VPNName: "hy", ListenPort: 443,
			Hy2ServerName: "example.com", Hy2MasqueradeURL: "http://127.0.0.1:8080",
			Hy2PendingPrompt: "", Prompt: "Masquerade:", Picker: []string{"None", "Proxy", "File"},
		})
		m.SetWizardPickerIdx(2)
		m.WizardCreateVPNPickerEnter(2)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", VPNName: "hy", ListenPort: 443,
			Hy2ServerName: "example.com", Hy2UpMbps: 100, Hy2DownMbps: 100, Hy2IgnoreBW: true,
			Hy2PendingPrompt: "down_mbps", Prompt: "Download bandwidth (Mbps) [100]:",
			Input: tui.NewTextInputForTest("100"),
		})
		m.WizardCreateVPNTextEnter("100")
	})

	t.Run("wireguard validate steps fail", func(t *testing.T) {
		m, svc := newTestServiceModel(t)
		createTestVPN(t, svc, "existing", 51820)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "wireguard", VPNName: "wg2", ListenPort: 51820,
			Prompt: "Subnet [10.8.0.1/24]:", Input: tui.NewTextInputForTest("10.9.0.1/24"),
		})
		m.WizardCreateVPNTextEnter("10.9.0.1/24")
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "wireguard", VPNName: "wg2", ListenPort: 51820,
			WGAddress: "10.9.0.1/24", WGMTU: 99999, Prompt: "MTU [1420, empty=default]:",
			Input: tui.NewTextInputForTest("99999"),
		})
		m.WizardCreateVPNTextEnter("99999")
	})

	t.Run("inbound trojan paths", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "trojan", VPNName: "tr", ListenPort: 443,
			TrojanServerName: "bad name!", Prompt: "TLS server name (SNI) [auto]:",
			Input: tui.NewTextInputForTest("bad name!"),
		})
		m.WizardCreateVPNTextEnter("bad name!")
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "trojan", VPNName: "tr", ListenPort: 443,
			TrojanServerName: "example.com", TrojanTransport: "ws", TrojanPendingPrompt: "path",
			Prompt: "Transport path:", Input: tui.NewTextInputForTest("/"),
		})
		m.WizardCreateVPNTextEnter("/")
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "trojan", VPNName: "tr", ListenPort: 443,
			TrojanServerName: "example.com", TrojanTransport: "ws", TrojanTransportPath: "/",
			TrojanPendingPrompt: "host", Prompt: "Transport host:", Input: tui.NewTextInputForTest("h"),
		})
		m.WizardCreateVPNTextEnter("h")
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "trojan", VPNName: "tr", ListenPort: 443,
			TrojanServerName: "example.com", Prompt: "Fallback port [0=disabled]:",
			Input: tui.NewTextInputForTest("70000"),
		})
		m.WizardCreateVPNTextEnter("70000")
	})

	t.Run("manage async errors and fallbacks", func(t *testing.T) {
		m, svc := newTestServiceModel(t)
		createTestVPN(t, svc, "web", 8080)
		ctx := context.Background()
		client, _, _ := svc.AddClient(ctx, service.AddClientInput{VPNName: "web", Name: "phone"}, true)
		_ = client
		vpn := orchestration.VPNView{Name: "web", Protocol: "http", Enabled: false, Listen: domain.ListenOptions{ListenPort: 8080}}
		cview := orchestration.ClientView{Name: "phone", Enabled: false}

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditClient, Step: 3, EditField: "Status", VPNName: "web", ClientName: "phone", SelectedClient: cview, Picker: []string{"Active", "Inactive"}})
		m.SetWizardPickerIdx(1)
		next, cmd := m.WizardPickerEnter()
		completeAsync(t, next, cmd)

		broken := closedOrchModel(t)
		broken.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditClient, Step: 3, EditField: "Name", VPNName: "web", ClientName: "phone", Input: tui.NewTextInputForTest("x")})
		broken.SetWizardInputValue("x")
		next2, cmd2 := broken.WizardTextEnter()
		completeAsync(t, next2, cmd2)

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditClient, Step: 3, EditField: "BadField", VPNName: "web", ClientName: "phone"})
		m.WizardTextEnter()

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditVPN, Step: 2, EditField: "Name", VPNName: "web", SelectedVPN: vpn, Input: tui.NewTextInputForTest("web2")})
		m.SetWizardInputValue("web2")
		next3, cmd3 := m.WizardTextEnter()
		completeAsync(t, next3, cmd3)

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardRemoveClient, Step: 1, VPNName: "web", ClientName: "phone"})
		m.WizardAfterClientPick()
	})

	t.Run("wizard misc branches", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, StepType: tui.StepText, Prompt: "VPN name:", Input: tui.NewTextInputForTest("x")})
		m.SetWizardInputValue("x")
		m.WizardTextEnter()
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardAddClient, Step: 2, StepType: tui.StepText})
		m.WizardTextEnter()
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardAddClient, Step: 1, StepType: tui.StepPicker})
		m.WizardPickerEnter()

		m2, _ := newTestServiceModel(t)
		m2.SetMode(tui.ModeWizard)
		m2.SetWizard(tui.WizardStateForTest{Kind: tui.WizardSetSSHPort, StepType: tui.StepText})
		next, _ := m2.Update(tui.NewSSHPortSetMsgForTest(22, errors.New("x")))
		if !strings.Contains(next.Wizard().Prompt, "try again") {
			t.Fatal("expected ssh port error in updateWizard")
		}

		m2.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, StepType: tui.StepNotice, Notice: "a",
			WizardHistory: []tui.WizardStateForTest{{Prompt: "prev", StepType: tui.StepText}},
		})
		next2, _ := m2.Update(tui.NewProtocolListMsgForTest([]string{"socks5"}, nil))
		_ = next2
		if _, cmd := m2.WizardCreateVPNBack(); cmd == nil {
			t.Fatal("expected pop history cmd")
		}

		m2.SetMode(tui.ModeWizard)
		m2.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, StepType: tui.StepConfirm, Prompt: "Sure?"})
		_ = m2.View()
		m2.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, StepType: tui.StepNotice, Notice: "note"})
		m2.SetMessage("msg")
		_ = m2.View()

		m2.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "shadowsocks", Prompt: "Transport options:",
			Picker: append(orchestration.ShadowsocksTransportModes(), "extra"),
		})
		m.WizardCreateVPNPickerEnter(len(orchestration.ShadowsocksTransportModes()))

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Protocol: "socks5", Prompt: "Subnet [x]:"})
		m.WizardCreateVPNTextEnter("x")
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Prompt: "Bandwidth:", Protocol: "hysteria2"})
		m.WizardCreateVPNTextEnter("x")
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Prompt: "Client host [auto]:", TrojanPendingPrompt: "fallback", Protocol: "trojan"})
		m.WizardCreateVPNTextEnter("x")

		m2, svc := newTestServiceModel(t)
		createTestVPN(t, svc, "wgdup", 51820)
		m2.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "wireguard", VPNName: "wg3", ListenPort: 51820,
			WGAddress: "10.8.0.1/24", Prompt: "MTU [1420, empty=default]:", Input: tui.NewTextInputForTest("1420"),
		})
		m2.WizardCreateVPNTextEnter("1420")

		m2.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", VPNName: "hy", ListenPort: 443,
			Hy2ServerName: "example.com", Hy2MasqueradeURL: "://bad", Prompt: "Masquerade:",
			Picker: []string{"None", "Proxy", "File"},
		})
		m2.SetWizardPickerIdx(1)
		m2.WizardCreateVPNPickerEnter(1)

		m2.SetWizard(tui.WizardStateForTest{Kind: tui.WizardAddClient, Step: 2, VPNName: "web"})
		m2.WizardAfterClientPick()

		disabled := orchestration.ClientView{Name: "off", Enabled: false}
		m2.SetWizard(tui.WizardStateForTest{Kind: tui.WizardEditClient, Step: 2, EditField: "Status", SelectedClient: disabled, ClientName: "off"})
		m2.WizardShowEditClientValue()
	})
}

func TestCoverageRound10(t *testing.T) {
	t.Run("hy2 masquerade and bandwidth validate fail", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		base := tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", VPNName: "hy", ListenPort: 443,
			Hy2ServerName: "example.com", Hy2UpMbps: 100, Hy2DownMbps: 50, Hy2IgnoreBW: true,
		}
		m.SetWizard(base)
		next, _ := m.WizardAcceptHy2MasqueradeForTest(0)
		if next.Wizard().StepError == "" {
			t.Fatal("expected hy2 masquerade validate error")
		}

		m.SetWizard(base)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", VPNName: "hy", ListenPort: 443,
			Hy2ServerName: "example.com", Hy2UpMbps: 100, Hy2DownMbps: 50, Hy2IgnoreBW: true,
			Hy2PendingPrompt: "masquerade_proxy", Prompt: "Masquerade proxy URL [http://127.0.0.1:8080]:",
			Input: tui.NewTextInputForTest("http://127.0.0.1:8080"),
		})
		next, _ = m.WizardAcceptHy2MasqueradeDetailForTest("http://127.0.0.1:8080")
		if next.Wizard().StepError == "" {
			t.Fatal("expected hy2 masquerade detail validate error")
		}

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", VPNName: "hy", ListenPort: 443,
			Hy2ServerName: "example.com", Hy2PendingPrompt: "up_mbps",
			Prompt: "Upload bandwidth (Mbps) [100]:", Input: tui.NewTextInputForTest("200"),
		})
		m.WizardAcceptHy2BandwidthDetailForTest("200")

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", VPNName: "hy", ListenPort: 443,
			Hy2ServerName: "example.com", Hy2UpMbps: 0, Hy2PendingPrompt: "down_mbps",
			Prompt: "Download bandwidth (Mbps) [100]:", Input: tui.NewTextInputForTest(""),
		})
		m.WizardAcceptHy2BandwidthDetailForTest("")

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", VPNName: "hy", ListenPort: 443,
			Hy2ServerName: "example.com", Hy2UpMbps: 100, Hy2DownMbps: 50, Hy2IgnoreBW: true,
			Hy2PendingPrompt: "down_mbps", Prompt: "Download bandwidth (Mbps) [100]:",
			Input: tui.NewTextInputForTest("100"),
		})
		next, _ = m.WizardAcceptHy2BandwidthDetailForTest("100")
		if next.Wizard().StepError == "" {
			t.Fatal("expected hy2 bandwidth detail validate error")
		}

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", VPNName: "hy", ListenPort: 443,
			Hy2PendingPrompt: "other", Prompt: "other:",
		})
		m.WizardAcceptHy2BandwidthDetailForTest("x")
	})

	t.Run("entry handler fallthrough", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Step: 9, StepType: tui.StepText, Prompt: "unknown",
			Input: tui.NewTextInputForTest("x"),
		})
		m.WizardTextEnter()
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardEditClient, Step: 3, StepType: tui.StepText, EditField: "Bad",
			VPNName: "x", ClientName: "y", Input: tui.NewTextInputForTest("z"),
		})
		m.WizardTextEnter()
	})

	t.Run("dispatch pending fallthrough", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "hysteria2", Prompt: "other:",
			Hy2PendingPrompt: "down_mbps", Input: tui.NewTextInputForTest("100"),
		})
		m.WizardCreateVPNTextEnter("100")
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "trojan", Prompt: "TLS server name (SNI) [auto]:",
			Input: tui.NewTextInputForTest("example.com"),
		})
		m.WizardCreateVPNTextEnter("example.com")
	})

	t.Run("wireguard validate fail", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "wireguard", VPNName: "wg-new", ListenPort: 51820,
			Prompt: "Subnet [10.8.0.1/24]:", Input: tui.NewTextInputForTest(""),
		})
		m.WizardAcceptWireguardSubnetForTest("")

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "wireguard", VPNName: "wg-new", ListenPort: 51820,
			HTTPTLS: true, Prompt: "Subnet [10.8.0.1/24]:", Input: tui.NewTextInputForTest("10.9.0.1/24"),
		})
		next, _ := m.WizardAcceptWireguardSubnetForTest("10.9.0.1/24")
		if next.Wizard().StepError == "" {
			t.Fatal("expected wireguard subnet validate error")
		}

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "wireguard", VPNName: "wg-new", ListenPort: 51820,
			HTTPTLS: true, WGAddress: "10.9.0.1/24",
			Prompt: "MTU [1420, empty=default]:", Input: tui.NewTextInputForTest("1420"),
		})
		next, _ = m.WizardAcceptWireguardMTUForTest("1420")
		if next.Wizard().StepError == "" {
			t.Fatal("expected wireguard mtu validate error")
		}
	})

	t.Run("inbound transport and trojan validate fail", func(t *testing.T) {
		m, _ := newTestServiceModel(t)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "trojan", VPNName: "tr", ListenPort: 443,
			HTTPTLS: true, Prompt: "TLS server name (SNI) [auto]:",
			Input: tui.NewTextInputForTest("example.com"),
		})
		next, _ := m.WizardAcceptTrojanSNI("example.com")
		if next.Wizard().StepError == "" {
			t.Fatal("expected trojan sni validate error")
		}

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "trojan", VPNName: "tr", ListenPort: 443,
			TrojanPendingPrompt: "other",
		})
		m.WizardShowTrojanTransportDetailInputForTest("x")

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "vless", VPNName: "vl", ListenPort: 443,
			VlessFlow: orchestration.VLESSFlowVision(), TrojanTransport: "grpc",
			TrojanPendingPrompt: "service_name", Prompt: "gRPC service name:",
			Input: tui.NewTextInputForTest(""),
		})
		m.WizardAcceptTrojanTransportDetailForTest("")

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "trojan", VPNName: "tr", ListenPort: 443,
			HTTPTLS: true, Prompt: "Transport options:",
		})
		next, _ = m.WizardHandleInboundTransportSelectionForTest("Direct")
		if next.Wizard().StepError == "" {
			t.Fatal("expected direct transport validate error")
		}
		m.WizardHandleInboundTransportSelectionForTest("unknown-mode")

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "trojan", VPNName: "tr", ListenPort: 443,
			TrojanPendingPrompt: "other", Prompt: "Transport option:",
			Input: tui.NewTextInputForTest("x"),
		})
		m.WizardAcceptTrojanTransportDetailForTest("x")

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "trojan", VPNName: "tr", ListenPort: 443,
			HTTPTLS: true, TrojanServerName: "example.com",
			Prompt: "Fallback port [0=disabled]:", Input: tui.NewTextInputForTest("443"),
		})
		next, _ = m.WizardAcceptTrojanFallbackForTest("443")
		if next.Wizard().StepError == "" {
			t.Fatal("expected fallback validate error")
		}
	})

	t.Run("dispatch and edit client fallthrough", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "trojan", CreateStep: 99,
			Prompt: "TLS server name (SNI) [auto]:", Input: tui.NewTextInputForTest("example.com"),
		})
		m.WizardCreateVPNTextEnter("example.com")

		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardEditClient, Step: 3, StepType: tui.StepText, EditField: "Bad",
			VPNName: "x", ClientName: "y", Input: tui.NewTextInputForTest("renamed"),
		})
		m.SetWizardInputValue("renamed")
		m.WizardTextEnterManageForTest("renamed")
	})

	t.Run("nav render and ss default", func(t *testing.T) {
		m := tui.NewModelForTest(nil, nil)
		if _, cmd := m.WizardPopHistoryForTest(); cmd != nil {
			t.Fatal("expected nil pop on empty history")
		}

		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, StepType: tui.StepNotice, Notice: "old"})
		m.WizardAdvanceCreateVPNForTest(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, StepType: tui.StepNotice, Notice: "new",
		}, nil)

		m.SetMode(tui.ModeWizard)
		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, StepType: tui.StepConfirm, Prompt: "Go?",
		})
		if !strings.Contains(m.View(), "Press Enter to confirm") {
			t.Fatal("expected confirm panel")
		}

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, StepType: tui.StepText, Prompt: "Port [443]:", StepError: "bad port",
			Input: tui.NewTextInputForTest(""),
		})
		if !strings.Contains(m.View(), "bad port") {
			t.Fatal("expected step error in view")
		}

		m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardAddClient, StepType: tui.StepNotice, Notice: ""})
		help := m.RenderHelpForTest()
		if !strings.Contains(help, "esc cancel") || strings.Contains(help, "enter/esc cancel") {
			t.Fatal("expected empty-notice help branch")
		}

		m.SetWizard(tui.WizardStateForTest{
			Kind: tui.WizardCreateVPN, Protocol: "shadowsocks", VPNName: "ss", ListenPort: 8388,
		})
		m.WizardAcceptSSTransportModeForTest("unknown-mode")
	})
}
