package tui

import (
	"context"
	"os"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/ivan-khludov/obscura/internal/config"
	"github.com/ivan-khludov/obscura/internal/orchestration"
)

// Test screen and mode aliases for external tests.
const (
	ScreenMain    = int(screenMain)
	ScreenVPNs    = int(screenVPNs)
	ScreenClients = int(screenClients)
	ScreenSystem  = int(screenSystem)
	ScreenBackup  = int(screenBackup)

	ModeMenu   = int(modeMenu)
	ModeWizard = int(modeWizard)

	StepText    = int(stepText)
	StepPicker  = int(stepPicker)
	StepConfirm = int(stepConfirm)
	StepNotice  = int(stepNotice)

	WizardCreateVPN     = int(wizardCreateVPN)
	WizardAddClient     = int(wizardAddClient)
	WizardShowClient    = int(wizardShowClient)
	WizardRemoveClient  = int(wizardRemoveClient)
	WizardDeleteVPN     = int(wizardDeleteVPN)
	WizardRestoreBackup = int(wizardRestoreBackup)
	WizardSetCongestion = int(wizardSetCongestion)
	WizardSetSSHPort    = int(wizardSetSSHPort)
	WizardEditVPN       = int(wizardEditVPN)
	WizardEditClient    = int(wizardEditClient)
)

// WizardStateForTest mirrors wizardState for external test setup.
type WizardStateForTest struct {
	Kind                       int
	Step                       int
	VPNs                       []orchestration.VPNView
	Clients                    []orchestration.ClientView
	VPNName                    string
	ClientName                 string
	Protocol                   string
	SSMethod                   string
	SSTransport                string
	SSMultiplex                bool
	SSMultiplexPadding         bool
	SSShadowTLS                bool
	SSShadowTLSHandshake       string
	SSPlugin                   string
	SSPluginOpts               string
	HTTPTLS                    bool
	TrojanServerName           string
	TrojanTransport            string
	TrojanMultiplex            bool
	TrojanMultiplexPadding     bool
	TrojanTransportPath        string
	TrojanTransportHost        string
	TrojanTransportServiceName string
	TrojanFallbackPort         int
	TrojanPendingPrompt        string
	VMessNoTLS                 bool
	VlessReality               bool
	VlessFlow                  string
	RealityUTLSFingerprint     string
	Hy2ServerName              string
	Hy2IgnoreBW                bool
	Hy2UpMbps                  int
	Hy2DownMbps                int
	Hy2ObfsPassword            string
	Hy2MasqueradeURL           string
	Hy2PendingPrompt           string
	TuicServerName             string
	TuicCongestionControl      string
	TuicZeroRTT                bool
	WGAddress                  string
	WGSystem                   bool
	WGMTU                      int
	WGPrompt                   string
	ListenPort                 int
	ClientHost                 string
	PickerIdx                  int
	Picker                     []string
	ProtocolOptions            []string
	StepType                   int
	CreateStep                 int
	Prompt                     string
	PromptHint                 string
	PickerHints                []string
	Notice                     string
	Loading                    bool
	Input                      textinput.Model
	Backups                    []orchestration.BackupEntry
	BackupPath                 string
	CongestionOptions          []string
	CongestionCurrent          string
	SelectedVPN                orchestration.VPNView
	SelectedClient             orchestration.ClientView
	EditField                  string
	WizardHistory              []WizardStateForTest
	BasePrompt                 string
	StepError                  string
}

func wizardStateFromTest(w WizardStateForTest) wizardState {
	out := wizardState{
		kind:                       wizardKind(w.Kind),
		step:                       w.Step,
		vpns:                       w.VPNs,
		clients:                    w.Clients,
		vpnName:                    w.VPNName,
		clientName:                 w.ClientName,
		protocol:                   w.Protocol,
		ssMethod:                   w.SSMethod,
		ssTransport:                w.SSTransport,
		ssMultiplex:                w.SSMultiplex,
		ssMultiplexPadding:         w.SSMultiplexPadding,
		ssShadowTLS:                w.SSShadowTLS,
		ssShadowTLSHandshake:       w.SSShadowTLSHandshake,
		ssPlugin:                   w.SSPlugin,
		ssPluginOpts:               w.SSPluginOpts,
		httpTLS:                    w.HTTPTLS,
		trojanServerName:           w.TrojanServerName,
		trojanTransport:            w.TrojanTransport,
		trojanMultiplex:            w.TrojanMultiplex,
		trojanMultiplexPadding:     w.TrojanMultiplexPadding,
		trojanTransportPath:        w.TrojanTransportPath,
		trojanTransportHost:        w.TrojanTransportHost,
		trojanTransportServiceName: w.TrojanTransportServiceName,
		trojanFallbackPort:         w.TrojanFallbackPort,
		trojanPendingPrompt:        w.TrojanPendingPrompt,
		vmessNoTLS:                 w.VMessNoTLS,
		vlessReality:               w.VlessReality,
		vlessFlow:                  w.VlessFlow,
		realityUTLSFingerprint:     w.RealityUTLSFingerprint,
		hy2ServerName:              w.Hy2ServerName,
		hy2IgnoreBW:                w.Hy2IgnoreBW,
		hy2UpMbps:                  w.Hy2UpMbps,
		hy2DownMbps:                w.Hy2DownMbps,
		hy2ObfsPassword:            w.Hy2ObfsPassword,
		hy2MasqueradeURL:           w.Hy2MasqueradeURL,
		hy2PendingPrompt:           w.Hy2PendingPrompt,
		tuicServerName:             w.TuicServerName,
		tuicCongestionControl:      w.TuicCongestionControl,
		tuicZeroRTT:                w.TuicZeroRTT,
		wgAddress:                  w.WGAddress,
		wgSystem:                   w.WGSystem,
		wgMTU:                      w.WGMTU,
		wgPrompt:                   w.WGPrompt,
		listenPort:                 w.ListenPort,
		clientHost:                 w.ClientHost,
		pickerIdx:                  w.PickerIdx,
		picker:                     w.Picker,
		protocolOptions:            w.ProtocolOptions,
		stepType:                   stepKind(w.StepType),
		createStep:                 createStepID(w.CreateStep),
		prompt:                     w.Prompt,
		promptHint:                 w.PromptHint,
		pickerHints:                w.PickerHints,
		notice:                     w.Notice,
		loading:                    w.Loading,
		input:                      w.Input,
		backups:                    w.Backups,
		backupPath:                 w.BackupPath,
		congestionOptions:          w.CongestionOptions,
		congestionCurrent:          w.CongestionCurrent,
		selectedVPN:                w.SelectedVPN,
		selectedClient:             w.SelectedClient,
		editField:                  w.EditField,
		basePrompt:                 w.BasePrompt,
		stepError:                  w.StepError,
	}
	if len(w.WizardHistory) > 0 {
		out.wizardHistory = make([]wizardState, len(w.WizardHistory))
		for i, h := range w.WizardHistory {
			out.wizardHistory[i] = wizardStateFromTest(h)
		}
	}
	return out
}

func wizardStateToTest(w wizardState) WizardStateForTest {
	out := WizardStateForTest{
		Kind:                       int(w.kind),
		Step:                       w.step,
		VPNs:                       w.vpns,
		Clients:                    w.clients,
		VPNName:                    w.vpnName,
		ClientName:                 w.clientName,
		Protocol:                   w.protocol,
		SSMethod:                   w.ssMethod,
		SSTransport:                w.ssTransport,
		SSMultiplex:                w.ssMultiplex,
		SSMultiplexPadding:         w.ssMultiplexPadding,
		SSShadowTLS:                w.ssShadowTLS,
		SSShadowTLSHandshake:       w.ssShadowTLSHandshake,
		SSPlugin:                   w.ssPlugin,
		SSPluginOpts:               w.ssPluginOpts,
		HTTPTLS:                    w.httpTLS,
		TrojanServerName:           w.trojanServerName,
		TrojanTransport:            w.trojanTransport,
		TrojanMultiplex:            w.trojanMultiplex,
		TrojanMultiplexPadding:     w.trojanMultiplexPadding,
		TrojanTransportPath:        w.trojanTransportPath,
		TrojanTransportHost:        w.trojanTransportHost,
		TrojanTransportServiceName: w.trojanTransportServiceName,
		TrojanFallbackPort:         w.trojanFallbackPort,
		TrojanPendingPrompt:        w.trojanPendingPrompt,
		VMessNoTLS:                 w.vmessNoTLS,
		VlessReality:               w.vlessReality,
		VlessFlow:                  w.vlessFlow,
		RealityUTLSFingerprint:     w.realityUTLSFingerprint,
		Hy2ServerName:              w.hy2ServerName,
		Hy2IgnoreBW:                w.hy2IgnoreBW,
		Hy2UpMbps:                  w.hy2UpMbps,
		Hy2DownMbps:                w.hy2DownMbps,
		Hy2ObfsPassword:            w.hy2ObfsPassword,
		Hy2MasqueradeURL:           w.hy2MasqueradeURL,
		Hy2PendingPrompt:           w.hy2PendingPrompt,
		TuicServerName:             w.tuicServerName,
		TuicCongestionControl:      w.tuicCongestionControl,
		TuicZeroRTT:                w.tuicZeroRTT,
		WGAddress:                  w.wgAddress,
		WGSystem:                   w.wgSystem,
		WGMTU:                      w.wgMTU,
		WGPrompt:                   w.wgPrompt,
		ListenPort:                 w.listenPort,
		ClientHost:                 w.clientHost,
		PickerIdx:                  w.pickerIdx,
		Picker:                     w.picker,
		ProtocolOptions:            w.protocolOptions,
		StepType:                   int(w.stepType),
		CreateStep:                 int(w.createStep),
		Prompt:                     w.prompt,
		PromptHint:                 w.promptHint,
		PickerHints:                w.pickerHints,
		Notice:                     w.notice,
		Loading:                    w.loading,
		Input:                      w.input,
		Backups:                    w.backups,
		BackupPath:                 w.backupPath,
		CongestionOptions:          w.congestionOptions,
		CongestionCurrent:          w.congestionCurrent,
		SelectedVPN:                w.selectedVPN,
		SelectedClient:             w.selectedClient,
		EditField:                  w.editField,
		BasePrompt:                 w.basePrompt,
		StepError:                  w.stepError,
	}
	if len(w.wizardHistory) > 0 {
		out.WizardHistory = make([]WizardStateForTest, len(w.wizardHistory))
		for i, h := range w.wizardHistory {
			out.WizardHistory[i] = wizardStateToTest(h)
		}
	}
	return out
}

// TestModel wraps model for external tests.
type TestModel struct {
	m model
}

// NewModelForTest constructs a TUI model for tests.
func NewModelForTest(app *config.App, orch ...*orchestration.Facade) *TestModel {
	return &TestModel{m: newModel(app, orch...)}
}

func wrapModel(m model) *TestModel { return &TestModel{m: m} }

// Init implements tea.Model.
func (tm *TestModel) Init() tea.Cmd { return tm.m.Init() }

// Update implements tea.Model.
func (tm *TestModel) Update(msg tea.Msg) (*TestModel, tea.Cmd) {
	next, cmd := tm.m.Update(msg)
	return wrapModel(next.(model)), cmd
}

// View implements tea.Model.
func (tm *TestModel) View() string { return tm.m.View() }

// HandleSelect executes the current menu selection.
func (tm *TestModel) HandleSelect() (*TestModel, tea.Cmd) {
	next, cmd := tm.m.handleSelect()
	return wrapModel(next), cmd
}

// GoBackMain returns to the main menu.
func (tm *TestModel) GoBackMain() (*TestModel, tea.Cmd) {
	next, cmd := tm.m.goBackMain()
	return wrapModel(next), cmd
}

// OpenSubmenu opens a submenu screen.
func (tm *TestModel) OpenSubmenu(s int, items []string) (*TestModel, tea.Cmd) {
	next, cmd := tm.m.openSubmenu(screen(s), items)
	return wrapModel(next), cmd
}

// StartSSHPortWizard begins the SSH port wizard.
func (tm *TestModel) StartSSHPortWizard() (*TestModel, tea.Cmd) {
	next, cmd := tm.m.startSSHPortWizard()
	return wrapModel(next), cmd
}

// StartWizard begins a wizard flow.
func (tm *TestModel) StartWizard(kind int) (*TestModel, tea.Cmd) {
	next, cmd := tm.m.startWizard(wizardKind(kind))
	return wrapModel(next), cmd
}

// WizardTextEnter submits the current text step.
func (tm *TestModel) WizardTextEnter() (*TestModel, tea.Cmd) {
	next, cmd := tm.m.wizardTextEnter()
	return wrapModel(next), cmd
}

// WizardPickerEnter submits the current picker selection.
func (tm *TestModel) WizardPickerEnter() (*TestModel, tea.Cmd) {
	next, cmd := tm.m.wizardPickerEnter()
	return wrapModel(next), cmd
}

// WizardShowCreatePortInput shows the create-VPN port step.
func (tm *TestModel) WizardShowCreatePortInput() (*TestModel, tea.Cmd) {
	next, cmd := tm.m.wizardShowCreatePortInput()
	return wrapModel(next), cmd
}

// WizardAcceptCreatePort validates and accepts a port value.
func (tm *TestModel) WizardAcceptCreatePort(val string) (*TestModel, tea.Cmd) {
	next, cmd := tm.m.wizardAcceptCreatePort(val)
	return wrapModel(next), cmd
}

// WizardAcceptSSTransport accepts a shadowsocks transport selection.
func (tm *TestModel) WizardAcceptSSTransport(idx int) (*TestModel, tea.Cmd) {
	next, cmd := tm.m.wizardAcceptSSTransport(idx)
	return wrapModel(next), cmd
}

// WizardAcceptTrojanSNI accepts trojan SNI input.
func (tm *TestModel) WizardAcceptTrojanSNI(val string) (*TestModel, tea.Cmd) {
	next, cmd := tm.m.wizardAcceptTrojanSNI(val)
	return wrapModel(next), cmd
}

// WizardShowEditVPNFields shows VPN edit field picker.
func (tm *TestModel) WizardShowEditVPNFields() (*TestModel, tea.Cmd) {
	next, cmd := tm.m.wizardShowEditVPNFields()
	return wrapModel(next), cmd
}

// WizardShowEditClientFields shows client edit field picker.
func (tm *TestModel) WizardShowEditClientFields() (*TestModel, tea.Cmd) {
	next, cmd := tm.m.wizardShowEditClientFields()
	return wrapModel(next), cmd
}

// WizardCreateVPNPickerEnter dispatches create-VPN picker input.
func (tm *TestModel) WizardCreateVPNPickerEnter(idx int) (*TestModel, tea.Cmd, bool) {
	next, cmd, ok := tm.m.wizardCreateVPNPickerEnter(idx)
	return wrapModel(next), cmd, ok
}

// WizardCreateVPNTextEnter dispatches create-VPN text input.
func (tm *TestModel) WizardCreateVPNTextEnter(val string) (*TestModel, tea.Cmd, bool) {
	next, cmd, ok := tm.m.wizardCreateVPNTextEnter(val)
	return wrapModel(next), cmd, ok
}

// WizardConfirmEnter submits the current confirm step.
func (tm *TestModel) WizardConfirmEnter() (*TestModel, tea.Cmd) {
	next, cmd := tm.m.wizardConfirmEnter()
	return wrapModel(next), cmd
}

// WizardAcceptSSHPort validates and submits SSH port input.
func (tm *TestModel) WizardAcceptSSHPort(val string) (*TestModel, tea.Cmd) {
	next, cmd := tm.m.wizardAcceptSSHPort(val)
	return wrapModel(next), cmd
}

// WizardFinishSetCongestion applies the selected congestion algorithm.
func (tm *TestModel) WizardFinishSetCongestion(algorithm string) (*TestModel, tea.Cmd) {
	next, cmd := tm.m.wizardFinishSetCongestion(algorithm)
	return wrapModel(next), cmd
}

// WizardAfterVPNPick advances manage wizard after VPN selection.
func (tm *TestModel) WizardAfterVPNPick() (*TestModel, tea.Cmd) {
	next, cmd := tm.m.wizardAfterVPNPick()
	return wrapModel(next), cmd
}

// WizardAfterClientPick advances manage wizard after client selection.
func (tm *TestModel) WizardAfterClientPick() (*TestModel, tea.Cmd) {
	next, cmd := tm.m.wizardAfterClientPick()
	return wrapModel(next), cmd
}

// WizardShowEditVPNValue shows the edit-VPN value input for the selected field.
func (tm *TestModel) WizardShowEditVPNValue() (*TestModel, tea.Cmd) {
	next, cmd := tm.m.wizardShowEditVPNValue()
	return wrapModel(next), cmd
}

// WizardShowEditClientValue shows the edit-client value input for the selected field.
func (tm *TestModel) WizardShowEditClientValue() (*TestModel, tea.Cmd) {
	next, cmd := tm.m.wizardShowEditClientValue()
	return wrapModel(next), cmd
}

// WizardPopHistoryForTest pops the last wizard history entry.
func (tm *TestModel) WizardPopHistoryForTest() (*TestModel, tea.Cmd) {
	next, cmd := tm.m.wizardPopHistory()
	return wrapModel(next), cmd
}

// WizardHandleInboundTransportSelectionForTest applies an inbound transport mode.
func (tm *TestModel) WizardHandleInboundTransportSelectionForTest(mode string) (*TestModel, tea.Cmd) {
	next, cmd := tm.m.wizardHandleInboundTransportSelection(mode)
	return wrapModel(next), cmd
}

// WizardAdvanceCreateVPNForTest records wizard history when the step changes.
func (tm *TestModel) WizardAdvanceCreateVPNForTest(next WizardStateForTest, cmd tea.Cmd) (*TestModel, tea.Cmd, bool) {
	n := tm.m
	n.wizard = wizardStateFromTest(next)
	out, c, ok := tm.m.wizardAdvanceCreateVPN(n, cmd)
	return wrapModel(out), c, ok
}

// WizardShowTrojanTransportDetailInputForTest shows transport detail text input.
func (tm *TestModel) WizardShowTrojanTransportDetailInputForTest(defaultVal string) (*TestModel, tea.Cmd) {
	next, cmd := tm.m.wizardShowTrojanTransportDetailInput(defaultVal)
	return wrapModel(next), cmd
}

// WizardAcceptTrojanTransportDetailForTest accepts transport detail text input.
func (tm *TestModel) WizardAcceptTrojanTransportDetailForTest(val string) (*TestModel, tea.Cmd) {
	next, cmd := tm.m.wizardAcceptTrojanTransportDetail(val)
	return wrapModel(next), cmd
}

// WizardAcceptTrojanFallbackForTest accepts trojan fallback port input.
func (tm *TestModel) WizardAcceptTrojanFallbackForTest(val string) (*TestModel, tea.Cmd) {
	next, cmd := tm.m.wizardAcceptTrojanFallback(val)
	return wrapModel(next), cmd
}

// WizardTextEnterManageForTest dispatches manage-wizard text input.
func (tm *TestModel) WizardTextEnterManageForTest(val string) (*TestModel, tea.Cmd, bool) {
	next, cmd, ok := tm.m.wizardTextEnterManage(val)
	return wrapModel(next), cmd, ok
}

// WizardAcceptHy2MasqueradeForTest accepts hysteria2 masquerade picker input.
func (tm *TestModel) WizardAcceptHy2MasqueradeForTest(idx int) (*TestModel, tea.Cmd) {
	next, cmd := tm.m.wizardAcceptHy2Masquerade(idx)
	return wrapModel(next), cmd
}

// WizardAcceptHy2MasqueradeDetailForTest accepts hysteria2 masquerade detail input.
func (tm *TestModel) WizardAcceptHy2MasqueradeDetailForTest(val string) (*TestModel, tea.Cmd) {
	next, cmd := tm.m.wizardAcceptHy2MasqueradeDetail(val)
	return wrapModel(next), cmd
}

// WizardAcceptHy2BandwidthDetailForTest accepts hysteria2 bandwidth detail input.
func (tm *TestModel) WizardAcceptHy2BandwidthDetailForTest(val string) (*TestModel, tea.Cmd) {
	next, cmd := tm.m.wizardAcceptHy2BandwidthDetail(val)
	return wrapModel(next), cmd
}

// WizardAcceptWireguardSubnetForTest accepts wireguard subnet input.
func (tm *TestModel) WizardAcceptWireguardSubnetForTest(val string) (*TestModel, tea.Cmd) {
	next, cmd := tm.m.wizardAcceptWireguardSubnet(val)
	return wrapModel(next), cmd
}

// WizardAcceptWireguardMTUForTest accepts wireguard MTU input.
func (tm *TestModel) WizardAcceptWireguardMTUForTest(val string) (*TestModel, tea.Cmd) {
	next, cmd := tm.m.wizardAcceptWireguardMTU(val)
	return wrapModel(next), cmd
}

// WizardAcceptSSTransportModeForTest accepts a shadowsocks transport mode by name.
func (tm *TestModel) WizardAcceptSSTransportModeForTest(mode string) (*TestModel, tea.Cmd) {
	next, cmd := tm.m.wizardAcceptSSTransportMode(mode)
	return wrapModel(next), cmd
}

// RenderHelpForTest returns wizard/menu help text.
func (tm *TestModel) RenderHelpForTest() string { return tm.m.renderHelp() }

// WizardCreateVPNBack pops create-VPN wizard history.
func (tm *TestModel) WizardCreateVPNBack() (*TestModel, tea.Cmd) {
	next, cmd := tm.m.wizardCreateVPNBack()
	return wrapModel(next), cmd
}

// CancelWizard exits wizard mode.
func (tm *TestModel) CancelWizard() (*TestModel, tea.Cmd) {
	next, cmd := tm.m.cancelWizard()
	return wrapModel(next), cmd
}

// StartCongestionWizard begins the TCP congestion wizard.
func (tm *TestModel) StartCongestionWizard() (*TestModel, tea.Cmd) {
	next, cmd := tm.m.startCongestionWizard()
	return wrapModel(next), cmd
}

// StartRestoreBackupWizard begins the restore backup wizard.
func (tm *TestModel) StartRestoreBackupWizard() (*TestModel, tea.Cmd) {
	next, cmd := tm.m.startRestoreBackupWizard()
	return wrapModel(next), cmd
}

// SetQuitting sets the quitting flag for View tests.
func (tm *TestModel) SetQuitting(v bool) { tm.m.quitting = v }

// FrozenCursor returns the frozen menu cursor during wizard mode.
func (tm *TestModel) FrozenCursor() int { return tm.m.frozenCursor }

// MainMenuItems returns menu items for the current bootstrap state.
func (tm *TestModel) MainMenuItems() []string { return tm.m.mainMenuItems() }

// RenderPanel renders the status/wizard panel.
func (tm *TestModel) RenderPanel() string { return tm.m.renderPanel() }

// Screen returns the current screen.
func (tm *TestModel) Screen() int { return int(tm.m.screen) }

// Cursor returns the menu cursor position.
func (tm *TestModel) Cursor() int { return tm.m.cursor }

// Mode returns the UI mode.
func (tm *TestModel) Mode() int { return int(tm.m.mode) }

// Message returns the status message.
func (tm *TestModel) Message() string { return tm.m.message }

// Busy reports whether an async action is running.
func (tm *TestModel) Busy() bool { return tm.m.busy }

// BusyPercent returns bootstrap progress percent (-1 when inactive).
func (tm *TestModel) BusyPercent() int { return tm.m.busyPercent }

// BusyLabel returns the busy spinner label.
func (tm *TestModel) BusyLabel() string { return tm.m.busyLabel }

// IgnoreEnter reports whether Enter is debounced.
func (tm *TestModel) IgnoreEnter() bool { return tm.m.ignoreEnter }

// Bootstrapped reports whether the server is bootstrapped.
func (tm *TestModel) Bootstrapped() bool { return tm.m.bootstrapped }

// Items returns current menu items.
func (tm *TestModel) Items() []string { return tm.m.items }

// Quitting reports whether the TUI is exiting.
func (tm *TestModel) Quitting() bool { return tm.m.quitting }

// Wizard returns the current wizard state snapshot.
func (tm *TestModel) Wizard() WizardStateForTest { return wizardStateToTest(tm.m.wizard) }

// SetScreen sets the current screen.
func (tm *TestModel) SetScreen(s int) { tm.m.screen = screen(s) }

// SetCursor sets the menu cursor.
func (tm *TestModel) SetCursor(c int) { tm.m.cursor = c }

// SetMode sets the UI mode.
func (tm *TestModel) SetMode(mode int) { tm.m.mode = uiMode(mode) }

// SetBootstrapped sets bootstrap state.
func (tm *TestModel) SetBootstrapped(v bool) { tm.m.bootstrapped = v }

// SetMessage sets the status message.
func (tm *TestModel) SetMessage(msg string) { tm.m.message = msg }

// SetBusy sets the busy flag.
func (tm *TestModel) SetBusy(v bool) { tm.m.busy = v }

// SetBusyPercent sets bootstrap progress percent.
func (tm *TestModel) SetBusyPercent(p int) { tm.m.busyPercent = p }

// SetBusyLabel sets the busy label.
func (tm *TestModel) SetBusyLabel(label string) { tm.m.busyLabel = label }

// SetIgnoreEnter sets enter debounce state.
func (tm *TestModel) SetIgnoreEnter(v bool) { tm.m.ignoreEnter = v }

// SetItems sets menu items.
func (tm *TestModel) SetItems(items []string) { tm.m.items = items }

// SetFrozenCursor sets the frozen menu cursor during wizard mode.
func (tm *TestModel) SetFrozenCursor(c int) { tm.m.frozenCursor = c }

// SetBootstrapCh sets the bootstrap progress channel.
func (tm *TestModel) SetBootstrapCh(ch chan tea.Msg) { tm.m.bootstrapCh = ch }

// SetWizard replaces wizard state from a test snapshot.
func (tm *TestModel) SetWizard(w WizardStateForTest) { tm.m.wizard = wizardStateFromTest(w) }

// SetWizardInputValue sets the wizard text input value.
func (tm *TestModel) SetWizardInputValue(v string) { tm.m.wizard.input.SetValue(v) }

// SetWizardPickerIdx sets the wizard picker cursor index.
func (tm *TestModel) SetWizardPickerIdx(idx int) { tm.m.wizard.pickerIdx = idx }

// WizardInputValue returns the wizard text input value.
func (tm *TestModel) WizardInputValue() string { return tm.m.wizard.input.Value() }

// SetOrch injects the orchestration facade for tests.
func (tm *TestModel) SetOrch(orch *orchestration.Facade) { tm.m.orch = orch }

// --- Message constructors.

// ActionDoneMsg carries async action completion for tests.
type ActionDoneMsg = actionDoneMsg

// NewActionDoneMsgForTest builds an action completion message for tests.
func NewActionDoneMsgForTest(text string, runErr error, refreshMenu bool) ActionDoneMsg {
	return ActionDoneMsg{text: text, runErr: runErr, refreshMenu: refreshMenu}
}

// NewBootstrapProgressMsgForTest builds a bootstrap progress message for tests.
func NewBootstrapProgressMsgForTest(label string, percent int) BootstrapProgressMsg {
	return BootstrapProgressMsg{label: label, percent: percent}
}

// NewBootstrapDoneMsgForTest builds a bootstrap completion message for tests.
func NewBootstrapDoneMsgForTest(err error) BootstrapDoneMsg {
	return BootstrapDoneMsg{err: err}
}

// NewMenuStatusMsgForTest builds a menu status message for tests.
func NewMenuStatusMsgForTest(bootstrapped bool) MenuStatusMsg {
	return MenuStatusMsg{bootstrapped: bootstrapped}
}

// NewCongestionListMsgForTest builds a congestion list message for tests.
func NewCongestionListMsgForTest(algorithms []string, current string, err error) CongestionListMsg {
	return CongestionListMsg{algorithms: algorithms, current: current, err: err}
}

// ClearIgnoreEnterMsg clears enter debounce for tests.
type ClearIgnoreEnterMsg = clearIgnoreEnterMsg

// BootstrapProgressMsg carries bootstrap progress for tests.
type BootstrapProgressMsg = bootstrapProgressMsg

// BootstrapDoneMsg carries bootstrap completion for tests.
type BootstrapDoneMsg = bootstrapDoneMsg

// MenuStatusMsg carries menu bootstrap status for tests.
type MenuStatusMsg = menuStatusMsg

// ProtocolListMsg carries protocol list load results for tests.
type ProtocolListMsg = protocolListMsg

// NewProtocolListMsgForTest builds a protocol list message for tests.
func NewProtocolListMsgForTest(protocols []string, err error) ProtocolListMsg {
	return ProtocolListMsg{protocols: protocols, err: err}
}

// VPNListMsg carries VPN list load results for tests.
type VPNListMsg = vpnListMsg

// NewVPNListMsgForTest builds a VPN list message for tests.
func NewVPNListMsgForTest(vpns []orchestration.VPNView, err error) VPNListMsg {
	return VPNListMsg{vpns: vpns, err: err}
}

// ClientListMsg carries client list load results for tests.
type ClientListMsg = clientListMsg

// NewClientListMsgForTest builds a client list message for tests.
func NewClientListMsgForTest(clients []orchestration.ClientView, err error) ClientListMsg {
	return ClientListMsg{clients: clients, err: err}
}

// BackupListMsg carries backup list load results for tests.
type BackupListMsg = backupListMsg

// NewBackupListMsgForTest builds a backup list message for tests.
func NewBackupListMsgForTest(backups []orchestration.BackupEntry, err error) BackupListMsg {
	return BackupListMsg{backups: backups, err: err}
}

// CongestionListMsg carries congestion list load results for tests.
type CongestionListMsg = congestionListMsg

// SSHPortSetMsg carries SSH port set results for tests.
type SSHPortSetMsg = sshPortSetMsg

// NewSSHPortSetMsgForTest builds an SSH port set result message for tests.
func NewSSHPortSetMsgForTest(port int, err error) SSHPortSetMsg {
	return SSHPortSetMsg{port: port, err: err}
}

// SSHPortSetErrorForTest returns the error from an SSH port set message.
func SSHPortSetErrorForTest(msg SSHPortSetMsg) error { return msg.err }

// IsTTYForTest reports whether f is a terminal device.
func IsTTYForTest(f *os.File) bool { return IsTTY(f) }

// CreateVPNResultMsg carries create-VPN results for tests.
type CreateVPNResultMsg = createVPNResultMsg

// NewCreateVPNResultMsgForTest builds a create-VPN result message for tests.
func NewCreateVPNResultMsgForTest(text string, err error) CreateVPNResultMsg {
	return CreateVPNResultMsg{text: text, err: err}
}

// CreateVPNResultErrorForTest returns the error from a create-VPN result message.
func CreateVPNResultErrorForTest(msg CreateVPNResultMsg) error { return msg.err }

// MenuStatusBootstrappedForTest returns bootstrap state from a menu status message.
func MenuStatusBootstrappedForTest(msg MenuStatusMsg) bool { return msg.bootstrapped }

// TickMsg triggers spinner ticks for tests.
type TickMsg = tickMsg

// --- Pure function exports.

// NewTextInputForTest constructs a focused text input for tests.
func NewTextInputForTest(placeholder string) textinput.Model {
	return newTextInput(placeholder)
}

// VPNMenuItemsForTest returns VPN submenu items.
func VPNMenuItemsForTest() []string { return vpnMenuItems() }

// ClientMenuItemsForTest returns client submenu items.
func ClientMenuItemsForTest() []string { return clientMenuItems() }

// SystemMenuItemsForTest returns system submenu items.
func SystemMenuItemsForTest() []string { return systemMenuItems() }

// BackupMenuItemsForTest returns backup submenu items.
func BackupMenuItemsForTest() []string { return backupMenuItems() }

// FormatBackupListForTest formats backup entries for display.
func FormatBackupListForTest(entries []orchestration.BackupEntry) string {
	return formatBackupList(entries)
}

// FormatClientExportForTest formats client URI with optional QR.
func FormatClientExportForTest(uri, qrContent string) (string, error) {
	return formatClientExport(uri, qrContent)
}

// FormatURIWithQRForTest formats a URI with QR code.
func FormatURIWithQRForTest(uri string) (string, error) {
	return formatURIWithQR(uri)
}

// BuildCreateVPNRequestForTest builds a create-VPN request from wizard state.
func BuildCreateVPNRequestForTest(w WizardStateForTest) orchestration.CreateVPNRequest {
	return buildCreateVPNRequest(wizardStateFromTest(w))
}

// ProgressBarForTest renders a progress bar for tests.
func ProgressBarForTest(percent, width int) string { return progressBar(percent, width) }

// RenderBootstrapProgressForTest renders bootstrap progress for tests.
func RenderBootstrapProgressForTest(label string, percent int) string {
	return renderBootstrapProgress(label, percent)
}

// VPNLabelForTest formats a VPN list label.
func VPNLabelForTest(v orchestration.VPNView) string { return vpnLabel(v) }

// ClientLabelForTest formats a client list label.
func ClientLabelForTest(c orchestration.ClientView) string { return clientLabel(c) }

// StripWizardErrorSuffixForTest strips error suffix from wizard prompts.
func StripWizardErrorSuffixForTest(prompt string) string { return stripWizardErrorSuffix(prompt) }

// SnapshotForHistoryForTest snapshots wizard state for history navigation.
func SnapshotForHistoryForTest(w WizardStateForTest) WizardStateForTest {
	return wizardStateToTest(wizardStateFromTest(w).snapshotForHistory())
}

// ActiveHintForTest returns the active wizard hint.
func ActiveHintForTest(w WizardStateForTest) string {
	state := wizardStateFromTest(w)
	return state.activeHint()
}

// SetPickerStepForTest configures a picker step on wizard state.
func SetPickerStepForTest(w *WizardStateForTest, prompt, hint string, items, itemHints []string) {
	state := wizardStateFromTest(*w)
	state.setPickerStep(prompt, hint, items, itemHints)
	*w = wizardStateToTest(state)
}

// ShadowsocksTransportPickerHintsForTest returns SS transport picker hints.
func ShadowsocksTransportPickerHintsForTest() []string { return ssTransportPickerHints() }

// InboundTransportPickerHintsForTest returns inbound transport picker hints.
func InboundTransportPickerHintsForTest(protocol string) []string {
	return inboundTransportPickerHints(protocol)
}

// VlessFlowPickerHintsForTest returns VLESS flow picker hints.
func VlessFlowPickerHintsForTest() []string { return vlessFlowPickerHints() }

// SSCipherPickerHintsForTest returns shadowsocks cipher picker hints.
func SSCipherPickerHintsForTest() []string { return ssCipherPickerHints() }

// WGInterfacePickerHintsForTest returns WireGuard interface picker hints.
func WGInterfacePickerHintsForTest() []string { return wgInterfacePickerHints() }

// TuicCongestionPickerHintsForTest returns TUIC congestion picker hints.
func TuicCongestionPickerHintsForTest() []string { return tuicCongestionPickerHints() }

// TuicZeroRTTPickerHintsForTest returns TUIC 0-RTT picker hints.
func TuicZeroRTTPickerHintsForTest() []string { return tuicZeroRTTPickerHints() }

// Hy2BandwidthPickerHintsForTest returns hysteria2 bandwidth picker hints.
func Hy2BandwidthPickerHintsForTest() []string { return hy2BandwidthPickerHints() }

// Hy2ObfsPickerHintsForTest returns hysteria2 obfs picker hints.
func Hy2ObfsPickerHintsForTest() []string { return hy2ObfsPickerHints() }

// Hy2MasqueradePickerHintsForTest returns hysteria2 masquerade picker hints.
func Hy2MasqueradePickerHintsForTest() []string { return hy2MasqueradePickerHints() }

// HTTPTLSPickerHintsForTest returns HTTP TLS picker hints.
func HTTPTLSPickerHintsForTest() []string { return httpTLSPickerHints() }

// VMessTLSPickerHintsForTest returns VMess TLS picker hints.
func VMessTLSPickerHintsForTest() []string { return vmessTLSPickerHints() }

// VlessTLSModePickerHintsForTest returns VLESS TLS mode picker hints.
func VlessTLSModePickerHintsForTest() []string { return vlessTLSModePickerHints() }

// RealityUTLSFingerprintPickerHintsForTest returns Reality fingerprint picker hints.
func RealityUTLSFingerprintPickerHintsForTest() []string {
	return realityUTLSFingerprintPickerHints()
}

// RealityUTLSFingerprintModesForTest returns Reality fingerprint mode names.
func RealityUTLSFingerprintModesForTest() []string {
	return append([]string{}, realityUTLSFingerprintModes...)
}

// EditVPNFieldsForTest returns editable VPN fields for a protocol.
func EditVPNFieldsForTest(vpn orchestration.VPNView) []string { return editVPNFields(vpn) }

// LoadVPNsCmdForTest returns a command that loads VPNs.
func LoadVPNsCmdForTest(orch *orchestration.Facade) tea.Cmd { return loadVPNsCmd(orch) }

// LoadClientsCmdForTest returns a command that loads clients.
func LoadClientsCmdForTest(orch *orchestration.Facade, vpnName string) tea.Cmd {
	return loadClientsCmd(orch, vpnName)
}

// LoadBackupsCmdForTest returns a command that loads backups.
func LoadBackupsCmdForTest(orch *orchestration.Facade) tea.Cmd { return loadBackupsCmd(orch) }

// LoadCongestionCmdForTest returns a command that loads congestion algorithms.
func LoadCongestionCmdForTest(orch *orchestration.Facade) tea.Cmd { return loadCongestionCmd(orch) }

// LoadProtocolsCmdForTest returns a command that loads protocols.
func LoadProtocolsCmdForTest(orch *orchestration.Facade) tea.Cmd { return loadProtocolsCmd(orch) }

// LoadMenuStatusCmdForTest returns a command that loads menu bootstrap status.
func LoadMenuStatusCmdForTest(orch *orchestration.Facade) tea.Cmd { return loadMenuStatusCmd(orch) }

// CreateVPNCmdForTest returns a command that creates a VPN asynchronously.
func CreateVPNCmdForTest(orch *orchestration.Facade, req orchestration.CreateVPNRequest) tea.Cmd {
	return createVPNCmd(orch, req)
}

// WaitBootstrapCmdForTest waits on a bootstrap channel.
func WaitBootstrapCmdForTest(ch <-chan tea.Msg) tea.Cmd { return waitBootstrapCmd(ch) }

// TickCmdForTest returns a spinner tick command.
func TickCmdForTest() tea.Cmd { return tickCmd() }

// ClearIgnoreEnterCmdForTest returns an enter-debounce clear command.
func ClearIgnoreEnterCmdForTest() tea.Cmd { return clearIgnoreEnterCmd() }

// RunDefaultBootstrapRunnerForTest runs the production bootstrap goroutine for tests.
func RunDefaultBootstrapRunnerForTest(orch *orchestration.Facade, ch chan tea.Msg) {
	defaultBootstrapRunner(orch, ch)
}

// InferCreateStepFromPromptForTest maps wizard prompt text to create step id.
func InferCreateStepFromPromptForTest(w WizardStateForTest) int {
	return int(inferCreateStepFromPrompt(wizardStateFromTest(w)))
}

// SSCipherHintForTest returns the hint for a shadowsocks cipher name.
func SSCipherHintForTest(method string) string { return ssCipherHint(method) }

// ProtocolHintForTest returns the hint for a protocol name.
func ProtocolHintForTest(name string) string { return protocolHint(name) }

// RunForTest starts the TUI using the configured program factory.
func RunForTest(ctx context.Context, orch *orchestration.Facade, app *config.App) error {
	return Run(ctx, orch, app)
}

// DefaultIsTTYForTest runs the built-in TTY detector.
func DefaultIsTTYForTest(f *os.File) bool { return defaultIsTTY(f) }

// ResetIsTTYForTest restores the default TTY detector; returns restore func.
func ResetIsTTYForTest() func() {
	return SetIsTTYForTest(defaultIsTTY)
}

// SetIsTTYForTest overrides TTY detection; returns restore func.
func SetIsTTYForTest(fn func(*os.File) bool) func() {
	old := isTTYFn
	isTTYFn = fn
	return func() { isTTYFn = old }
}

// SetProgramFactoryForTest overrides tea program construction; returns restore func.
func SetProgramFactoryForTest(fn programFactoryType) func() {
	old := programFactory
	programFactory = fn
	return func() { programFactory = old }
}

// NewProgramRunnerForTest constructs a program runner via the configured factory.
func NewProgramRunnerForTest(tm *TestModel, opts ...tea.ProgramOption) programRunner {
	return programFactory(tm.m, opts...)
}

// SetProgramFactoryStubForTest installs a stub Run func for Run tests; returns restore.
func SetProgramFactoryStubForTest(stub func(tea.Model) (tea.Model, error)) func() {
	return SetProgramFactoryForTest(func(m tea.Model, _ ...tea.ProgramOption) programRunner {
		return programRunnerStub{stub: stub, m: m}
	})
}

type programRunnerStub struct {
	stub func(tea.Model) (tea.Model, error)
	m    tea.Model
}

func (p programRunnerStub) Run() (tea.Model, error) {
	return p.stub(p.m)
}

// SetBootstrapRunnerForTest overrides bootstrap goroutine; returns restore func.
func SetBootstrapRunnerForTest(fn bootstrapRunner) func() {
	old := bootstrapRunnerFn
	bootstrapRunnerFn = fn
	return func() { bootstrapRunnerFn = old }
}
