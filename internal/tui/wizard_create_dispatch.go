package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/ivan-khludov/obscura/internal/orchestration"
)

// wizardCreateVPNPickerEnter handles create-VPN wizard picker or text input.
func (m model) wizardCreateVPNPickerEnter(idx int) (model, tea.Cmd, bool) {
	step := m.wizard.createStep
	if step == createStepUnknown {
		step = inferCreateStepFromPrompt(m.wizard)
	}
	switch step {
	case createStepProtocol:
		return m.wizardHandleCreateProtocolPicker(idx)
	case createStepCipher:
		return m.wizardHandleCreateCipherPicker(idx)
	case createStepEnableTLS:
		return m.wizardHandleEnableTLSPicker(idx)
	case createStepTLSMode:
		return m.wizardHandleTLSModePicker(idx)
	case createStepTransport:
		return m.wizardHandleTransportPicker(idx)
	case createStepVLESSFlow:
		return m.wizardHandleVlessFlowPicker(idx)
	case createStepRealityFingerprint:
		return m.wizardHandleRealityFingerprintPicker(idx)
	case createStepWireguardInterface:
		return m.wizardHandleWireguardInterfacePicker(idx)
	case createStepTUICCongestion:
		return m.wizardHandleTuicCongestionPicker(idx)
	case createStepTUICZeroRTT:
		return m.wizardHandleTuicZeroRTTPicker(idx)
	case createStepHy2Bandwidth:
		return m.wizardHandleHy2BandwidthPicker(idx)
	case createStepHy2Obfs:
		return m.wizardHandleHy2ObfsPicker(idx)
	case createStepHy2Masquerade:
		return m.wizardHandleHy2MasqueradePicker(idx)
	}
	return m, nil, false
}

// wizardPrepareClientHostStep asks for an optional client connect host before client name.
func (m model) wizardPrepareClientHostStep() (model, tea.Cmd) {
	m.wizard.setCreateTextStep(createStepClientHost, "Client host [auto]:", hintClientHost, "")
	return m, textinput.Blink
}

// wizardPrepareClientNameStep manages wizard state, validation, or navigation.
func (m model) wizardPrepareClientNameStep() (model, tea.Cmd) {
	m.wizard.trojanPendingPrompt = ""
	m.wizard.hy2PendingPrompt = ""
	m.wizard.setCreateTextStep(createStepClientName, "Client name:", hintClientName, "phone")
	return m, textinput.Blink
}

// wizardCreateVPNTextEnter handles create-VPN wizard picker or text input.
func (m model) wizardCreateVPNTextEnter(val string) (model, tea.Cmd, bool) {
	step := m.wizard.createStep
	if step == createStepUnknown {
		step = inferCreateStepFromPrompt(m.wizard)
	}
	switch step {
	case createStepClientHost:
		m.wizard.clientHost = strings.TrimSpace(val)
		next, cmd := m.wizardPrepareClientNameStep()
		return next, cmd, true
	case createStepClientName:
		if val == "" {
			val = "phone"
		}
		m.wizard.clientName = val
		next, cmd := m.wizardFinishCreateVPN()
		return next, cmd, true
	case createStepFallback:
		return m.wizardHandleInboundFallbackText(val)
	case createStepTransportPath, createStepTransportServiceName, createStepTransportHost:
		return m.wizardHandleInboundTransportDetailText(val)
	case createStepPort, createStepWireguardSubnet, createStepWireguardMTU:
		return m.wizardHandlePortSubnetMTUText(val)
	case createStepShadowTLSHandshake:
		handshake := val
		if handshake == "" {
			handshake = orchestration.DefaultShadowsocksHandshake()
		}
		m.wizard.ssShadowTLSHandshake = handshake
		m.wizard.step++
		next, cmd := m.wizardPrepareClientHostStep()
		return next, cmd, true
	case createStepSNI:
		return m.wizardHandleProtocolSpecificText(val)
	case createStepHy2BandwidthUp, createStepHy2BandwidthDown, createStepHy2MasqueradeProxy, createStepHy2MasqueradeFile:
		return m.wizardHandleHy2PendingText(val)
	}
	if next, cmd, ok := m.wizardHandleTrojanPendingText(val); ok {
		return next, cmd, true
	}
	if next, cmd, ok := m.wizardHandleHy2PendingText(val); ok {
		return next, cmd, true
	}
	if next, cmd, ok := m.wizardHandleProtocolSpecificText(val); ok {
		return next, cmd, true
	}
	return m, nil, false
}

func (m model) wizardHandleCreateProtocolPicker(idx int) (model, tea.Cmd, bool) {
	if idx >= len(m.wizard.protocolOptions) {
		return m, nil, true
	}
	m.wizard.protocol = m.wizard.protocolOptions[idx]
	m.wizard.step++
	if m.wizard.protocol == "shadowsocks" {
		m.wizard.picker = orchestration.ShadowsocksMethods()
		m.wizard.pickerIdx = 0
		m.wizard.setCreatePickerStep(createStepCipher, "Select cipher:", "AEAD cipher for Shadowsocks encryption.", m.wizard.picker, ssCipherPickerHints())
		return m, nil, true
	}
	next, cmd := m.wizardShowCreatePortInput()
	return next, cmd, true
}

func (m model) wizardHandleCreateCipherPicker(idx int) (model, tea.Cmd, bool) {
	methods := orchestration.ShadowsocksMethods()
	if m.wizard.protocol != "shadowsocks" || idx >= len(methods) {
		return m, nil, true
	}
	m.wizard.ssMethod = methods[idx]
	m.wizard.step++
	next, cmd := m.wizardShowCreatePortInput()
	return next, cmd, true
}

func (m model) wizardHandleEnableTLSPicker(idx int) (model, tea.Cmd, bool) {
	switch m.wizard.protocol {
	case "http":
		m.wizard.httpTLS = idx == 1
		m.wizard.step++
		next, cmd := m.wizardPrepareClientHostStep()
		return next, cmd, true
	case "vmess":
		next, cmd := m.wizardAcceptVmessTLSMode(idx)
		return next, cmd, true
	default:
		return m, nil, false
	}
}

func (m model) wizardHandleTLSModePicker(idx int) (model, tea.Cmd, bool) {
	if m.wizard.protocol != "vless" {
		return m, nil, false
	}
	next, cmd := m.wizardAcceptVlessTLSMode(idx)
	return next, cmd, true
}

func (m model) wizardHandleTransportPicker(idx int) (model, tea.Cmd, bool) {
	switch m.wizard.protocol {
	case "shadowsocks":
		next, cmd := m.wizardAcceptSSTransport(idx)
		return next, cmd, true
	case "trojan", "vmess", "vless":
		next, cmd := m.wizardAcceptTrojanTransport(idx)
		return next, cmd, true
	default:
		return m, nil, false
	}
}

func (m model) wizardHandleVlessFlowPicker(idx int) (model, tea.Cmd, bool) {
	if m.wizard.protocol != "vless" {
		return m, nil, false
	}
	next, cmd := m.wizardAcceptVlessFlow(idx)
	return next, cmd, true
}

func (m model) wizardHandleRealityFingerprintPicker(idx int) (model, tea.Cmd, bool) {
	if m.wizard.protocol != "vless" {
		return m, nil, false
	}
	next, cmd := m.wizardAcceptRealityUTLSFingerprint(idx)
	return next, cmd, true
}

func (m model) wizardHandleWireguardInterfacePicker(idx int) (model, tea.Cmd, bool) {
	if m.wizard.protocol != "wireguard" {
		return m, nil, false
	}
	next, cmd := m.wizardAcceptWireguardSystem(idx)
	return next, cmd, true
}

func (m model) wizardHandleTuicCongestionPicker(idx int) (model, tea.Cmd, bool) {
	if m.wizard.protocol != "tuic" {
		return m, nil, false
	}
	next, cmd := m.wizardAcceptTuicCongestion(idx)
	return next, cmd, true
}

func (m model) wizardHandleTuicZeroRTTPicker(idx int) (model, tea.Cmd, bool) {
	if m.wizard.protocol != "tuic" {
		return m, nil, false
	}
	next, cmd := m.wizardAcceptTuicZeroRTT(idx)
	return next, cmd, true
}

func (m model) wizardHandleHy2BandwidthPicker(idx int) (model, tea.Cmd, bool) {
	if m.wizard.protocol != "hysteria2" {
		return m, nil, false
	}
	next, cmd := m.wizardAcceptHy2Bandwidth(idx)
	return next, cmd, true
}

func (m model) wizardHandleHy2ObfsPicker(idx int) (model, tea.Cmd, bool) {
	if m.wizard.protocol != "hysteria2" {
		return m, nil, false
	}
	next, cmd := m.wizardAcceptHy2Obfs(idx)
	return next, cmd, true
}

func (m model) wizardHandleHy2MasqueradePicker(idx int) (model, tea.Cmd, bool) {
	if m.wizard.protocol != "hysteria2" {
		return m, nil, false
	}
	next, cmd := m.wizardAcceptHy2Masquerade(idx)
	return next, cmd, true
}

func (m model) wizardHandleInboundFallbackText(val string) (model, tea.Cmd, bool) {
	switch m.wizard.protocol {
	case "trojan", "vmess", "vless":
		next, cmd := m.wizardAcceptTrojanFallback(val)
		return next, cmd, true
	default:
		return m, nil, false
	}
}

func (m model) wizardHandleInboundTransportDetailText(val string) (model, tea.Cmd, bool) {
	switch m.wizard.protocol {
	case "trojan", "vmess", "vless":
		next, cmd := m.wizardAcceptTrojanTransportDetail(val)
		return next, cmd, true
	default:
		return m, nil, false
	}
}

func (m model) wizardHandleTrojanPendingText(val string) (model, tea.Cmd, bool) {
	switch m.wizard.trojanPendingPrompt {
	case "path", "service_name", "host":
		return m.wizardHandleInboundTransportDetailText(val)
	case "fallback":
		return m.wizardHandleInboundFallbackText(val)
	default:
		return m, nil, false
	}
}

func (m model) wizardHandleHy2PendingText(val string) (model, tea.Cmd, bool) {
	switch m.wizard.hy2PendingPrompt {
	case "up_mbps", "down_mbps":
		if m.wizard.protocol == "hysteria2" {
			next, cmd := m.wizardAcceptHy2BandwidthDetail(val)
			return next, cmd, true
		}
	case "masquerade_proxy", "masquerade_file":
		if m.wizard.protocol == "hysteria2" {
			next, cmd := m.wizardAcceptHy2MasqueradeDetail(val)
			return next, cmd, true
		}
	}
	return m, nil, false
}

func (m model) wizardHandlePortSubnetMTUText(val string) (model, tea.Cmd, bool) {
	if strings.HasPrefix(m.wizard.prompt, "Port [") {
		next, cmd := m.wizardAcceptCreatePort(val)
		return next, cmd, true
	}
	if strings.HasPrefix(m.wizard.prompt, "Subnet [") && m.wizard.protocol == "wireguard" {
		next, cmd := m.wizardAcceptWireguardSubnet(val)
		return next, cmd, true
	}
	if strings.HasPrefix(m.wizard.prompt, "MTU [") && m.wizard.protocol == "wireguard" {
		next, cmd := m.wizardAcceptWireguardMTU(val)
		return next, cmd, true
	}
	return m, nil, false
}

func (m model) wizardHandleProtocolSpecificText(val string) (model, tea.Cmd, bool) {
	if strings.Contains(m.wizard.prompt, "SNI") || strings.Contains(m.wizard.prompt, "Reality handshake") {
		switch m.wizard.protocol {
		case "trojan", "vless":
			next, cmd := m.wizardAcceptTrojanSNI(val)
			return next, cmd, true
		case "vmess":
			if !m.wizard.vmessNoTLS {
				next, cmd := m.wizardAcceptTrojanSNI(val)
				return next, cmd, true
			}
		case "hysteria2":
			next, cmd := m.wizardAcceptHy2SNI(val)
			return next, cmd, true
		case "tuic":
			next, cmd := m.wizardAcceptTuicSNI(val)
			return next, cmd, true
		}
	}
	if (strings.HasPrefix(m.wizard.prompt, "Upload bandwidth") || strings.HasPrefix(m.wizard.prompt, "Download bandwidth")) && m.wizard.protocol == "hysteria2" {
		next, cmd := m.wizardAcceptHy2BandwidthDetail(val)
		return next, cmd, true
	}
	if (strings.HasPrefix(m.wizard.prompt, "Masquerade proxy URL") || strings.HasPrefix(m.wizard.prompt, "Masquerade file directory")) && m.wizard.protocol == "hysteria2" {
		next, cmd := m.wizardAcceptHy2MasqueradeDetail(val)
		return next, cmd, true
	}
	return m, nil, false
}
