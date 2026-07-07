package tui

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/lipgloss"

	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/sshd"
)

type uiMode int

const (
	modeMenu uiMode = iota
	modeWizard
)

type wizardKind int

const (
	wizardCreateVPN wizardKind = iota
	wizardAddClient
	wizardShowClient
	wizardRemoveClient
	wizardDeleteVPN
	wizardRestoreBackup
	wizardSetCongestion
	wizardSetSSHPort
	wizardEditVPN
	wizardEditClient
)

type stepKind int

const (
	stepText stepKind = iota
	stepPicker
	stepConfirm
	stepNotice
)

type createStepID int

const (
	createStepUnknown createStepID = iota
	createStepVPNName
	createStepProtocol
	createStepCipher
	createStepPort
	createStepEnableTLS
	createStepTLSMode
	createStepSNI
	createStepRealityFingerprint
	createStepVLESSFlow
	createStepTransport
	createStepTransportPath
	createStepTransportServiceName
	createStepTransportHost
	createStepFallback
	createStepWireguardSubnet
	createStepWireguardInterface
	createStepWireguardMTU
	createStepTUICCongestion
	createStepTUICZeroRTT
	createStepHy2Bandwidth
	createStepHy2BandwidthUp
	createStepHy2BandwidthDown
	createStepHy2Obfs
	createStepHy2Masquerade
	createStepHy2MasqueradeProxy
	createStepHy2MasqueradeFile
	createStepShadowTLSHandshake
	createStepClientHost
	createStepClientName
)

var hintStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))

type wizardState struct {
	kind                       wizardKind
	step                       int
	vpns                       []orchestration.VPNView
	clients                    []orchestration.ClientView
	vpnName                    string
	clientName                 string
	protocol                   string
	ssMethod                   string
	ssTransport                string
	ssMultiplex                bool
	ssMultiplexPadding         bool
	ssShadowTLS                bool
	ssShadowTLSHandshake       string
	ssPlugin                   string
	ssPluginOpts               string
	httpTLS                    bool
	trojanServerName           string
	trojanTransport            string
	trojanMultiplex            bool
	trojanMultiplexPadding     bool
	trojanTransportPath        string
	trojanTransportHost        string
	trojanTransportServiceName string
	trojanFallbackPort         int
	trojanPendingPrompt        string
	vmessNoTLS                 bool
	vlessReality               bool
	vlessFlow                  string
	realityUTLSFingerprint     string
	hy2ServerName              string
	hy2IgnoreBW                bool
	hy2UpMbps                  int
	hy2DownMbps                int
	hy2ObfsPassword            string
	hy2MasqueradeURL           string
	hy2PendingPrompt           string
	tuicServerName             string
	tuicCongestionControl      string
	tuicZeroRTT                bool
	wgAddress                  string
	wgSystem                   bool
	wgMTU                      int
	wgPrompt                   string
	listenPort                 int
	clientHost                 string
	pickerIdx                  int
	picker                     []string
	protocolOptions            []string
	stepType                   stepKind
	createStep                 createStepID
	prompt                     string
	promptHint                 string
	pickerHints                []string
	notice                     string
	loading                    bool
	input                      textinput.Model
	backups                    []orchestration.BackupEntry
	backupPath                 string
	congestionOptions          []string
	congestionCurrent          string
	selectedVPN                orchestration.VPNView
	selectedClient             orchestration.ClientView
	editField                  string
	wizardHistory              []wizardState
	basePrompt                 string
	stepError                  string
}

// snapshotForHistory performs an internal helper operation.
func (w wizardState) snapshotForHistory() wizardState {
	snap := w
	snap.wizardHistory = nil
	snap.stepError = ""
	return snap
}

// stripWizardErrorSuffix normalizes user input for validation or storage.
func stripWizardErrorSuffix(prompt string) string {
	if i := strings.Index(prompt, " ("); i > 0 && strings.Contains(prompt, "try again") {
		return prompt[:i]
	}
	return prompt
}

// configuredSSHPort performs an internal helper operation.
func (m model) configuredSSHPort() int {
	if m.orch == nil {
		return sshd.DefaultPort
	}
	status, _ := m.orch.GetSSHPortFromRequest(context.Background(), orchestration.SSHPortReadRequest{})
	return status.Port
}

// vpnLabel performs an internal helper operation.
func vpnLabel(v orchestration.VPNView) string {
	return fmt.Sprintf("%s :%d (%s)", v.Name, v.Listen.ListenPort, v.Protocol)
}

// clientLabel performs an internal helper operation.
func clientLabel(c orchestration.ClientView) string {
	return c.Name
}

// newTextInput constructs a new instance for internal use.
func newTextInput(placeholder string) textinput.Model {
	ti := textinput.New()
	ti.Placeholder = placeholder
	ti.Focus()
	ti.CharLimit = 128
	ti.Width = 40
	return ti
}
