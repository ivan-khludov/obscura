package tui

import (
	"context"
	"fmt"
	"strconv"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/ivan-khludov/obscura/internal/orchestration"
)

// applyVPNList applies transport, TLS preview, or option fields to protocol data.
func (m model) applyVPNList(msg vpnListMsg) (model, tea.Cmd) {
	m.wizard.loading = false
	if msg.err != nil {
		m.wizard.stepType = stepNotice
		m.wizard.notice = msg.err.Error()
		return m, nil
	}
	if len(msg.vpns) == 0 {
		m.wizard.stepType = stepNotice
		m.wizard.notice = "No VPNs — create one first"
		return m, nil
	}
	m.wizard.vpns = msg.vpns
	m.wizard.picker = make([]string, len(msg.vpns))
	for i, v := range msg.vpns {
		m.wizard.picker[i] = vpnLabel(v)
	}
	m.wizard.pickerIdx = 0
	m.wizard.stepType = stepPicker
	m.wizard.prompt = "Select VPN:"
	return m, nil
}

// applyProtocolList applies transport, TLS preview, or option fields to protocol data.
func (m model) applyProtocolList(msg protocolListMsg) (model, tea.Cmd) {
	m.wizard.loading = false
	if msg.err != nil {
		m.wizard.stepType = stepNotice
		m.wizard.notice = msg.err.Error()
		return m, nil
	}
	if len(msg.protocols) == 0 {
		m.wizard.stepType = stepNotice
		m.wizard.notice = "No protocols available"
		return m, nil
	}
	m.wizard.protocolOptions = msg.protocols
	m.wizard.setCreatePickerStep(createStepProtocol, "Select protocol:", hintSelectProtocol, msg.protocols, protocolPickerHints(msg.protocols))
	m.wizard.pickerIdx = 0
	return m, nil
}

// applyCongestionList applies transport, TLS preview, or option fields to protocol data.
func (m model) applyCongestionList(msg congestionListMsg) (model, tea.Cmd) {
	m.wizard.loading = false
	if msg.err != nil {
		m.wizard.stepType = stepNotice
		m.wizard.notice = msg.err.Error()
		return m, nil
	}
	if len(msg.algorithms) == 0 {
		m.wizard.stepType = stepNotice
		m.wizard.notice = "No congestion control algorithms available"
		return m, nil
	}
	m.wizard.congestionOptions = msg.algorithms
	m.wizard.congestionCurrent = msg.current
	m.wizard.picker = make([]string, len(msg.algorithms))
	m.wizard.pickerIdx = 0
	for i, a := range msg.algorithms {
		label := a
		if a == msg.current {
			label += " (current)"
			m.wizard.pickerIdx = i
		}
		m.wizard.picker[i] = label
	}
	m.wizard.stepType = stepPicker
	m.wizard.prompt = "Select TCP congestion control:"
	return m, nil
}

// applyBackupList applies transport, TLS preview, or option fields to protocol data.
func (m model) applyBackupList(msg backupListMsg) (model, tea.Cmd) {
	m.wizard.loading = false
	if msg.err != nil {
		m.wizard.stepType = stepNotice
		m.wizard.notice = msg.err.Error()
		return m, nil
	}
	if len(msg.backups) == 0 {
		m.wizard.stepType = stepNotice
		m.wizard.notice = "No backups — create one first"
		return m, nil
	}
	m.wizard.backups = msg.backups
	m.wizard.picker = make([]string, len(msg.backups))
	for i, b := range msg.backups {
		m.wizard.picker[i] = fmt.Sprintf("%s  (%s)", b.Name, b.ModTime.UTC().Format("2006-01-02 15:04"))
	}
	m.wizard.pickerIdx = 0
	m.wizard.stepType = stepPicker
	m.wizard.prompt = "Select backup:"
	return m, nil
}

// applyClientList applies transport, TLS preview, or option fields to protocol data.
func (m model) applyClientList(msg clientListMsg) (model, tea.Cmd) {
	m.wizard.loading = false
	if msg.err != nil {
		m.wizard.stepType = stepNotice
		m.wizard.notice = msg.err.Error()
		return m, nil
	}
	if len(msg.clients) == 0 {
		m.wizard.stepType = stepNotice
		m.wizard.notice = "No clients on this VPN"
		return m, nil
	}
	m.wizard.clients = msg.clients
	m.wizard.picker = make([]string, len(msg.clients))
	for i, c := range msg.clients {
		m.wizard.picker[i] = clientLabel(c)
	}
	m.wizard.pickerIdx = 0
	m.wizard.stepType = stepPicker
	m.wizard.prompt = "Select client:"
	return m, nil
}

// applyCreateVPNResult applies transport, TLS preview, or option fields to protocol data.
func (m model) applyCreateVPNResult(msg createVPNResultMsg) (model, tea.Cmd) {
	if msg.err != nil {
		m.wizard.stepType = stepText
		m.wizard.createStep = createStepClientName
		m.wizard.basePrompt = "Client name:"
		m.wizard.prompt = "Client name:"
		client := m.wizard.clientName
		if client == "" {
			client = "phone"
		}
		m.wizard.input = newTextInput(client)
		return m.wizardShowStepError(msg.err)
	}
	m = m.exitWizardForAction()
	m.message = msg.text
	m.ignoreEnter = true
	return m, tea.Batch(clearIgnoreEnterCmd(), loadMenuStatusCmd(m.orch))
}

// applySSHPortSet applies transport, TLS preview, or option fields to protocol data.
func (m model) applySSHPortSet(msg sshPortSetMsg) (model, tea.Cmd) {
	if msg.err != nil {
		currentResult, err := m.orch.GetSSHPortFromRequest(context.Background(), orchestration.SSHPortReadRequest{})
		current := msg.port
		if err == nil {
			current = currentResult.Port
		}
		m.wizard.stepType = stepText
		m.wizard.prompt = fmt.Sprintf("SSH port [%d]: (%s — try again)", current, msg.err.Error())
		m.wizard.input = newTextInput(strconv.Itoa(msg.port))
		return m, textinput.Blink
	}
	m = m.exitWizardForAction()
	return m.startAsyncRefresh(fmt.Sprintf("SSH port set to %d", msg.port), func() (string, error) {
		return fmt.Sprintf("SSH port set to %d — ensure firewall allows access on the new port", msg.port), nil
	})
}
