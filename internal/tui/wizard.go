package tui

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/ivan-khludov/obscura/internal/orchestration"
)

// wizardShowCreatePortInput switches the wizard to the CreatePortInput step.
func (m model) wizardShowCreatePortInput() (model, tea.Cmd) {
	defaultPort := orchestration.DefaultListenPort(m.wizard.protocol)
	m.wizard.setCreateTextStep(createStepPort, fmt.Sprintf("Port [%d]:", defaultPort), hintPort, strconv.Itoa(defaultPort))
	return m, textinput.Blink
}

// wizardAcceptCreatePort handles wizard input for CreatePort and advances or validates the step.
func (m model) wizardAcceptCreatePort(val string) (model, tea.Cmd) {
	defaultPort := orchestration.DefaultListenPort(m.wizard.protocol)
	port := defaultPort
	if s := val; s != "" {
		p, err := strconv.Atoi(s)
		if err != nil || p <= 0 || p > 65535 {
			m.wizard.basePrompt = fmt.Sprintf("Port [%d]:", defaultPort)
			return m.wizardShowStepError(fmt.Errorf("invalid port"))
		}
		port = p
	}
	if port == m.configuredSSHPort() {
		m.wizard.basePrompt = fmt.Sprintf("Port [%d]:", defaultPort)
		return m.wizardShowStepError(fmt.Errorf("port %d is reserved for SSH; choose another port", port))
	}
	if m.orch != nil {
		if err := m.orch.ValidateVPNListenPortFromRequest(context.Background(), orchestration.ValidateVPNListenPortRequest{Port: port}); err != nil {
			m.wizard.basePrompt = fmt.Sprintf("Port [%d]:", defaultPort)
			return m.wizardShowStepError(err)
		}
	}
	m.wizard.listenPort = port
	m.wizard.step++
	return m.wizardAdvanceAfterCreatePort()
}

// wizardPickerEnter manages wizard state, validation, or navigation.
func (m model) wizardPickerEnter() (model, tea.Cmd) {
	idx := m.wizard.pickerIdx
	if next, cmd, handled := m.wizardPickerEnterCreate(idx); handled {
		return next, cmd
	}
	if next, cmd, handled := m.wizardPickerEnterManage(idx); handled {
		return next, cmd
	}
	return m, nil
}

// wizardTextEnter manages wizard state, validation, or navigation.
func (m model) wizardTextEnter() (model, tea.Cmd) {
	val := strings.TrimSpace(m.wizard.input.Value())
	if next, cmd, handled := m.wizardTextEnterCreate(val); handled {
		return next, cmd
	}
	if next, cmd, handled := m.wizardTextEnterManage(val); handled {
		return next, cmd
	}
	return m, nil
}

// wizardConfirmEnter manages wizard state, validation, or navigation.
func (m model) wizardConfirmEnter() (model, tea.Cmd) {
	switch m.wizard.kind {
	case wizardRemoveClient:
		return m.wizardFinishRemoveClient()
	case wizardDeleteVPN:
		return m.wizardFinishDeleteVPN()
	case wizardRestoreBackup:
		return m.wizardFinishRestoreBackup()
	}
	return m, nil
}

// wizardFinishCreateVPN completes the CreateVPN wizard action.
func (m model) wizardFinishCreateVPN() (model, tea.Cmd) {
	req := buildCreateVPNRequest(m.wizard)
	if m.orch != nil {
		if err := m.orch.ValidateCreateVPNWizardStepFromRequest(context.Background(), req, orchestration.WizardComplete); err != nil {
			return m.wizardShowStepError(err)
		}
	}
	m.busy = true
	m.busyLabel = "Creating VPN…"
	return m, tea.Batch(tickCmd(), createVPNCmd(m.orch, req))
}

// wizardAcceptSSHPort handles wizard input for SSHPort and advances or validates the step.
func (m model) wizardAcceptSSHPort(val string) (model, tea.Cmd) {
	currentResult, err := m.orch.GetSSHPortFromRequest(context.Background(), orchestration.SSHPortReadRequest{})
	current := 22
	if err == nil {
		current = currentResult.Port
	}
	port := current
	if s := val; s != "" {
		p, err := strconv.Atoi(s)
		if err != nil || p <= 0 || p > 65535 {
			m.wizard.prompt = fmt.Sprintf("SSH port [%d]: (invalid — try again)", current)
			m.wizard.input.SetValue("")
			return m, textinput.Blink
		}
		port = p
	}
	if port == current {
		m.wizard.stepType = stepNotice
		m.wizard.notice = fmt.Sprintf("SSH port is already %d", port)
		return m, nil
	}
	orch := m.orch
	return m, func() tea.Msg {
		result, err := orch.SetSSHPortFromRequest(context.Background(), orchestration.SetSSHPortRequest{Port: port})
		if err != nil {
			return sshPortSetMsg{port: port, err: err}
		}
		return sshPortSetMsg{port: result.Port}
	}
}

// wizardFinishSetCongestion completes the SetCongestion wizard action.
func (m model) wizardFinishSetCongestion(algorithm string) (model, tea.Cmd) {
	orch := m.orch
	m = m.exitWizardForAction()
	return m.startAsync("Applying TCP congestion…", func() (string, error) {
		result, err := orch.SetCongestionFromRequest(context.Background(), orchestration.SetCongestionRequest{Algorithm: algorithm})
		if err != nil {
			return "", err
		}
		if !result.Changed {
			return fmt.Sprintf("%s is already active", result.Algorithm), nil
		}
		return fmt.Sprintf("TCP congestion control set to %s", algorithm), nil
	})
}

// wizardFinishRestoreBackup completes the RestoreBackup wizard action.
func (m model) wizardFinishRestoreBackup() (model, tea.Cmd) {
	path := m.wizard.backupPath
	orch := m.orch
	m = m.exitWizardForAction()
	return m.startAsyncRefresh("Restoring backup…", func() (string, error) {
		if _, err := orch.RestoreBackupFromRequest(context.Background(), orchestration.RestoreBackupRequest{ArchivePath: path}); err != nil {
			return "", err
		}
		return "Backup restored — restart obscura to reload state", nil
	})
}
