package tui

import (
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/ivan-khludov/obscura/internal/orchestration"
)

// wizardShowInboundTransportPicker switches the wizard to the InboundTransportPicker step.
func (m model) wizardShowInboundTransportPicker() (model, tea.Cmd) {
	modes := orchestration.InboundTransportModes(m.wizard.protocol)
	m.wizard.setCreatePickerStep(createStepTransport, "Transport options:", hintTransport, modes, inboundTransportPickerHints(m.wizard.protocol))
	m.wizard.pickerIdx = 0
	return m, nil
}

// wizardShowClientNameInput switches the wizard to the ClientNameInput step.
func (m model) wizardShowClientNameInput() (model, tea.Cmd) {
	m.wizard.step++
	return m.wizardPrepareClientHostStep()
}

// wizardAfterInboundTransport manages wizard state, validation, or navigation.
func (m model) wizardAfterInboundTransport() (model, tea.Cmd) {
	if m.wizard.protocol == "vmess" && m.wizard.vmessNoTLS {
		return m.wizardShowClientNameInput()
	}
	return m.wizardShowTrojanFallbackInput()
}

// wizardAfterInboundTransportValidated manages wizard state, validation, or navigation.
func (m model) wizardAfterInboundTransportValidated(step orchestration.WizardValidateStep) (model, tea.Cmd) {
	if next, cmd, ok := m.wizardValidateStep(step); !ok {
		return next, cmd
	}
	return m.wizardAfterInboundTransport()
}

// wizardAcceptVlessTLSMode handles wizard input for VlessTLSMode and advances or validates the step.
func (m model) wizardAcceptVlessTLSMode(idx int) (model, tea.Cmd) {
	m.wizard.vlessReality = idx == 1
	m.wizard.step++
	if m.wizard.vlessReality {
		m.wizard.setCreateTextStep(createStepSNI, "Reality handshake server [auto]:", hintRealityHS, "")
		return m, textinput.Blink
	}
	m.wizard.setCreateTextStep(createStepSNI, "TLS server name (SNI) [auto]:", hintSNITrojan, "")
	return m, textinput.Blink
}

// wizardShowRealityUTLSFingerprintPicker switches the wizard to the Reality uTLS fingerprint step.
func (m model) wizardShowRealityUTLSFingerprintPicker() (model, tea.Cmd) {
	m.wizard.setCreatePickerStep(createStepRealityFingerprint, "uTLS fingerprint:", hintRealityUTLSFP, realityUTLSFingerprintModes, realityUTLSFingerprintPickerHints())
	m.wizard.pickerIdx = 0
	return m, nil
}

// wizardAcceptRealityUTLSFingerprint handles wizard input for the Reality uTLS fingerprint picker.
func (m model) wizardAcceptRealityUTLSFingerprint(idx int) (model, tea.Cmd) {
	if idx >= len(realityUTLSFingerprintModes) {
		return m, nil
	}
	m.wizard.realityUTLSFingerprint = strings.ToLower(realityUTLSFingerprintModes[idx])
	m.wizard.step++
	return m.wizardShowVlessFlowPicker()
}

// wizardShowVlessFlowPicker switches the wizard to the VlessFlowPicker step.
func (m model) wizardShowVlessFlowPicker() (model, tea.Cmd) {
	m.wizard.setCreatePickerStep(createStepVLESSFlow, "VLESS flow:", hintVlessFlow, orchestration.VLESSFlowModes(), vlessFlowPickerHints())
	m.wizard.pickerIdx = 0
	return m, nil
}

// wizardAcceptVlessFlow handles wizard input for VlessFlow and advances or validates the step.
func (m model) wizardAcceptVlessFlow(idx int) (model, tea.Cmd) {
	if idx >= len(orchestration.VLESSFlowModes()) {
		return m, nil
	}
	m.wizard.vlessFlow = orchestration.VLESSFlowByIndex(idx)
	if next, cmd, ok := m.wizardValidateStep(orchestration.WizardAfterVlessFlow); !ok {
		return next, cmd
	}
	m.wizard.step++
	return m.wizardShowInboundTransportPicker()
}

// wizardAcceptVmessTLSMode handles wizard input for VmessTLSMode and advances or validates the step.
func (m model) wizardAcceptVmessTLSMode(idx int) (model, tea.Cmd) {
	m.wizard.vmessNoTLS = idx == 0
	m.wizard.step++
	if m.wizard.vmessNoTLS {
		return m.wizardShowInboundTransportPicker()
	}
	m.wizard.setCreateTextStep(createStepSNI, "TLS server name (SNI) [auto]:", hintSNITrojan, "")
	return m, textinput.Blink
}

// wizardAcceptTrojanSNI handles wizard input for TrojanSNI and advances or validates the step.
func (m model) wizardAcceptTrojanSNI(val string) (model, tea.Cmd) {
	m.wizard.trojanServerName = val
	if next, cmd, ok := m.wizardValidateStep(orchestration.WizardAfterSNI); !ok {
		return next, cmd
	}
	m.wizard.step++
	if m.wizard.protocol == "vless" {
		if m.wizard.vlessReality {
			return m.wizardShowRealityUTLSFingerprintPicker()
		}
		return m.wizardShowVlessFlowPicker()
	}
	return m.wizardShowInboundTransportPicker()
}

// wizardAcceptTrojanTransport handles wizard input for TrojanTransport and advances or validates the step.
func (m model) wizardAcceptTrojanTransport(idx int) (model, tea.Cmd) {
	modes := inboundModesForProtocol(m.wizard.protocol)
	if idx >= len(modes) {
		return m, nil
	}
	return m.wizardHandleInboundTransportSelection(modes[idx])
}

// wizardShowTrojanTransportDetailInput switches the wizard to the TrojanTransportDetailInput step.
func (m model) wizardShowTrojanTransportDetailInput(defaultVal string) (model, tea.Cmd) {
	m.wizard.step++
	switch m.wizard.trojanPendingPrompt {
	case "path":
		m.wizard.setCreateTextStep(createStepTransportPath, "Transport path:", hintTransportPath, defaultVal)
	case "service_name":
		m.wizard.setCreateTextStep(createStepTransportServiceName, "gRPC service name:", hintGRPCService, defaultVal)
	case "host":
		m.wizard.setCreateTextStep(createStepTransportHost, "Transport host:", hintTransportHost, defaultVal)
	default:
		m.wizard.setCreateTextStep(createStepTransportPath, "Transport option:", hintTransport, defaultVal)
	}
	return m, textinput.Blink
}

// wizardShowTrojanFallbackInput switches the wizard to the TrojanFallbackInput step.
func (m model) wizardShowTrojanFallbackInput() (model, tea.Cmd) {
	m.wizard.step++
	m.wizard.trojanPendingPrompt = "fallback"
	m.wizard.setCreateTextStep(createStepFallback, "Fallback port [0=disabled]:", hintFallback, "0")
	return m, textinput.Blink
}

// wizardAcceptTrojanTransportDetail handles wizard input for TrojanTransportDetail and advances or validates the step.
func (m model) wizardAcceptTrojanTransportDetail(val string) (model, tea.Cmd) {
	switch m.wizard.trojanPendingPrompt {
	case "path":
		if val == "" {
			val = "/"
		}
		m.wizard.trojanTransportPath = val
		if m.wizard.trojanTransport == "httpupgrade" || m.wizard.trojanTransport == "ws" {
			m.wizard.trojanPendingPrompt = "host"
			return m.wizardShowTrojanTransportDetailInput("")
		}
		return m.wizardAfterInboundTransportValidated(orchestration.WizardAfterTransportDetail)
	case "service_name":
		if val == "" {
			val = "TunService"
		}
		m.wizard.trojanTransportServiceName = val
		return m.wizardAfterInboundTransportValidated(orchestration.WizardAfterTransportDetail)
	case "host":
		m.wizard.trojanTransportHost = val
		return m.wizardAfterInboundTransportValidated(orchestration.WizardAfterTransportDetail)
	default:
		return m, nil
	}
}

// wizardAcceptTrojanFallback handles wizard input for TrojanFallback and advances or validates the step.
func (m model) wizardAcceptTrojanFallback(val string) (model, tea.Cmd) {
	port := 0
	if s := strings.TrimSpace(val); s != "" {
		p, err := strconv.Atoi(s)
		if err != nil || p < 0 || p > 65535 {
			m.wizard.setPrompt("Fallback port [0=disabled]: (invalid — try again)", hintFallback)
			m.wizard.input.SetValue("")
			return m, textinput.Blink
		}
		port = p
	}
	m.wizard.trojanFallbackPort = port
	if next, cmd, ok := m.wizardValidateStep(orchestration.WizardAfterFallback); !ok {
		return next, cmd
	}
	m.wizard.step++
	return m.wizardPrepareClientHostStep()
}
