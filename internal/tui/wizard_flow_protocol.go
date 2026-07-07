package tui

import (
	"fmt"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/ivan-khludov/obscura/internal/orchestration"
)

func (m model) wizardAdvanceAfterCreatePort() (model, tea.Cmd) {
	switch m.wizard.protocol {
	case "http":
		m.wizard.picker = []string{"No TLS", "Enable TLS"}
		m.wizard.pickerIdx = 0
		m.wizard.setCreatePickerStep(createStepEnableTLS, "Enable TLS?", hintHTTPTLS, m.wizard.picker, httpTLSPickerHints())
		return m, nil
	case "shadowsocks":
		return m.wizardShowSSTransportPicker()
	case "trojan":
		m.wizard.step++
		m.wizard.setCreateTextStep(createStepSNI, "TLS server name (SNI) [auto]:", hintSNITrojan, "")
		return m, textinput.Blink
	case "vmess":
		m.wizard.picker = []string{"No TLS", "Enable TLS"}
		m.wizard.pickerIdx = 1
		m.wizard.setCreatePickerStep(createStepEnableTLS, "Enable TLS?", hintEnableTLS, m.wizard.picker, vmessTLSPickerHints())
		return m, nil
	case "vless":
		m.wizard.picker = []string{"Standard TLS", "Reality"}
		m.wizard.pickerIdx = 0
		m.wizard.setCreatePickerStep(createStepTLSMode, "TLS mode:", hintTLSModePicker, m.wizard.picker, vlessTLSModePickerHints())
		return m, nil
	case "hysteria2", "tuic":
		m.wizard.step++
		m.wizard.setCreateTextStep(createStepSNI, "TLS server name (SNI) [auto]:", hintSNIHy2Tuic, "")
		return m, textinput.Blink
	case "wireguard":
		m.wizard.step++
		defaultAddress, _ := orchestration.WireguardDefaults()
		m.wizard.setCreateTextStep(createStepWireguardSubnet, fmt.Sprintf("Subnet [%s]:", defaultAddress), hintWGSubnet, defaultAddress)
		m.wizard.wgPrompt = "subnet"
		return m, textinput.Blink
	default:
		m.wizard.stepType = stepText
		return m.wizardPrepareClientHostStep()
	}
}

func inboundModesForProtocol(protocolName string) []string {
	return orchestration.InboundTransportModes(protocolName)
}

func (m model) wizardHandleInboundTransportSelection(mode string) (model, tea.Cmd) {
	m.wizard.trojanTransport = mode
	m.wizard.trojanMultiplex = false
	m.wizard.trojanMultiplexPadding = false
	m.wizard.trojanTransportPath = ""
	m.wizard.trojanTransportHost = ""
	m.wizard.trojanTransportServiceName = ""

	switch mode {
	case "Direct":
		m.wizard.trojanTransport = ""
		if next, cmd, ok := m.wizardValidateStep(orchestration.WizardAfterTransport); !ok {
			return next, cmd
		}
		return m.wizardAfterInboundTransport()
	case "Multiplex":
		m.wizard.trojanTransport = ""
		m.wizard.trojanMultiplex = true
		if next, cmd, ok := m.wizardValidateStep(orchestration.WizardAfterTransport); !ok {
			return next, cmd
		}
		return m.wizardAfterInboundTransport()
	case "Multiplex (padding)":
		m.wizard.trojanTransport = ""
		m.wizard.trojanMultiplex = true
		m.wizard.trojanMultiplexPadding = true
		if next, cmd, ok := m.wizardValidateStep(orchestration.WizardAfterTransport); !ok {
			return next, cmd
		}
		return m.wizardAfterInboundTransport()
	case "WebSocket":
		m.wizard.trojanTransport = "ws"
		m.wizard.trojanPendingPrompt = "path"
		if next, cmd, ok := m.wizardValidateStep(orchestration.WizardAfterTransport); !ok {
			return next, cmd
		}
		return m.wizardShowTrojanTransportDetailInput("/")
	case "gRPC":
		m.wizard.trojanTransport = "grpc"
		m.wizard.trojanPendingPrompt = "service_name"
		if next, cmd, ok := m.wizardValidateStep(orchestration.WizardAfterTransport); !ok {
			return next, cmd
		}
		return m.wizardShowTrojanTransportDetailInput("TunService")
	case "HTTP":
		m.wizard.trojanTransport = "http"
		m.wizard.trojanPendingPrompt = "path"
		if next, cmd, ok := m.wizardValidateStep(orchestration.WizardAfterTransport); !ok {
			return next, cmd
		}
		return m.wizardShowTrojanTransportDetailInput("/")
	case "HTTPUpgrade":
		m.wizard.trojanTransport = "httpupgrade"
		m.wizard.trojanPendingPrompt = "path"
		if next, cmd, ok := m.wizardValidateStep(orchestration.WizardAfterTransport); !ok {
			return next, cmd
		}
		return m.wizardShowTrojanTransportDetailInput("/")
	case "QUIC":
		m.wizard.trojanTransport = "quic"
		if next, cmd, ok := m.wizardValidateStep(orchestration.WizardAfterTransport); !ok {
			return next, cmd
		}
		return m.wizardAfterInboundTransport()
	default:
		return m, nil
	}
}
