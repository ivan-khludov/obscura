package tui

import (
	"context"
	"fmt"
	"strconv"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/ivan-khludov/obscura/internal/orchestration"
)

// wizardShowStepError switches the wizard to the StepError step.
func (m model) wizardShowStepError(err error) (model, tea.Cmd) {
	m.wizard.basePrompt = stripWizardErrorSuffix(m.wizard.prompt)
	m.wizard.stepError = err.Error()
	m.wizard.prompt = m.wizard.basePrompt
	var cmd tea.Cmd
	if m.wizard.stepType == stepText {
		cmd = textinput.Blink
	}
	return m, cmd
}

// wizardValidateStep manages wizard state, validation, or navigation.
func (m model) wizardValidateStep(step orchestration.WizardValidateStep) (model, tea.Cmd, bool) {
	if m.orch == nil {
		return m, nil, true
	}
	req := buildCreateVPNRequest(m.wizard)
	if err := m.orch.ValidateCreateVPNWizardStepFromRequest(context.Background(), req, step); err != nil {
		next, cmd := m.wizardShowStepError(err)
		return next, cmd, false
	}
	return m, nil, true
}

// wizardStepChanged manages wizard state, validation, or navigation.
func (m model) wizardStepChanged(next model) bool {
	if m.wizard.stepType != next.wizard.stepType {
		return true
	}
	if m.wizard.prompt != next.wizard.prompt {
		return true
	}
	if m.wizard.stepType == stepNotice && m.wizard.notice != next.wizard.notice {
		return true
	}
	return m.wizard.step != next.wizard.step
}

// wizardAdvanceCreateVPN manages wizard state, validation, or navigation.
func (m model) wizardAdvanceCreateVPN(next model, cmd tea.Cmd) (model, tea.Cmd, bool) {
	if !m.wizardStepChanged(next) {
		return next, cmd, true
	}
	snap := m.wizard.snapshotForHistory()
	hist := append(append([]wizardState{}, m.wizard.wizardHistory...), snap)
	next.wizard.wizardHistory = hist
	if next.wizard.prompt != m.wizard.prompt {
		next.wizard.basePrompt = next.wizard.prompt
	} else if next.wizard.basePrompt == "" {
		next.wizard.basePrompt = next.wizard.prompt
	}
	next.wizard.stepError = ""
	return next, cmd, true
}

// wizardPopHistory manages wizard state, validation, or navigation.
func (m model) wizardPopHistory() (model, tea.Cmd) {
	if len(m.wizard.wizardHistory) == 0 {
		return m, nil
	}
	idx := len(m.wizard.wizardHistory) - 1
	prev := m.wizard.wizardHistory[idx]
	prev.wizardHistory = append([]wizardState{}, m.wizard.wizardHistory[:idx]...)
	m.wizard = prev
	m.wizard.stepError = ""
	var cmd tea.Cmd
	if m.wizard.stepType == stepText {
		cmd = textinput.Blink
	}
	return m, cmd
}

// wizardCreateVPNBack handles create-VPN wizard picker or text input.
func (m model) wizardCreateVPNBack() (model, tea.Cmd) {
	if m.wizard.kind != wizardCreateVPN || len(m.wizard.wizardHistory) == 0 {
		return m, nil
	}
	return m.wizardPopHistory()
}

// startCongestionWizard starts a wizard or async operation.
func (m model) startCongestionWizard() (model, tea.Cmd) {
	m.mode = modeWizard
	m.frozenCursor = m.cursor
	m.message = ""
	m.wizard = wizardState{kind: wizardSetCongestion, loading: true}
	return m, loadCongestionCmd(m.orch)
}

// startSSHPortWizard starts a wizard or async operation.
func (m model) startSSHPortWizard() (model, tea.Cmd) {
	m.mode = modeWizard
	m.frozenCursor = m.cursor
	m.message = ""
	currentResult, err := m.orch.GetSSHPortFromRequest(context.Background(), orchestration.SSHPortReadRequest{})
	current := 22
	if err == nil {
		current = currentResult.Port
	}
	m.wizard = wizardState{
		kind:     wizardSetSSHPort,
		stepType: stepText,
		prompt:   fmt.Sprintf("SSH port [%d]:", current),
		input:    newTextInput(strconv.Itoa(current)),
	}
	return m, textinput.Blink
}

// startRestoreBackupWizard starts a wizard or async operation.
func (m model) startRestoreBackupWizard() (model, tea.Cmd) {
	m.mode = modeWizard
	m.frozenCursor = m.cursor
	m.message = ""
	m.wizard = wizardState{kind: wizardRestoreBackup, loading: true}
	return m, loadBackupsCmd(m.orch)
}

// startWizard starts a wizard or async operation.
func (m model) startWizard(kind wizardKind) (model, tea.Cmd) {
	if kind == wizardRestoreBackup {
		return m.startRestoreBackupWizard()
	}
	if kind == wizardSetCongestion {
		return m.startCongestionWizard()
	}
	if kind == wizardSetSSHPort {
		return m.startSSHPortWizard()
	}
	m.mode = modeWizard
	m.frozenCursor = m.cursor
	m.message = ""
	m.wizard = wizardState{kind: kind}

	switch kind {
	case wizardCreateVPN:
		m.wizard.setCreateTextStep(createStepVPNName, "VPN name:", hintVPNName, "my-vpn")
		return m, textinput.Blink
	case wizardAddClient, wizardShowClient, wizardRemoveClient, wizardDeleteVPN, wizardEditVPN, wizardEditClient:
		m.wizard.loading = true
		return m, loadVPNsCmd(m.orch)
	default:
		return m.cancelWizard()
	}
}

// cancelWizard exits or cancels the current wizard or screen.
func (m model) cancelWizard() (model, tea.Cmd) {
	m.mode = modeMenu
	m.wizard = wizardState{}
	return m, nil
}
