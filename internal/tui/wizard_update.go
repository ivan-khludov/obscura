package tui

import tea "github.com/charmbracelet/bubbletea"

// updateWizard handles TUI events or user actions.
func (m model) updateWizard(msg tea.Msg) (model, tea.Cmd) {
	switch msg := msg.(type) {
	case vpnListMsg:
		return m.applyVPNList(msg)
	case backupListMsg:
		return m.applyBackupList(msg)
	case protocolListMsg:
		return m.applyProtocolList(msg)
	case congestionListMsg:
		return m.applyCongestionList(msg)
	case clientListMsg:
		return m.applyClientList(msg)
	case tea.KeyMsg:
		if m.wizard.stepType == stepText {
			switch msg.String() {
			case "ctrl+c":
				m.quitting = true
				return m, tea.Quit
			case "esc":
				return m.cancelWizard()
			case "ctrl+p":
				if m.wizard.kind == wizardCreateVPN {
					return m.wizardCreateVPNBack()
				}
			case "enter":
				var cmd tea.Cmd
				m, cmd = m.wizardTextEnter()
				return m, cmd
			default:
				var cmd tea.Cmd
				m.wizard.input, cmd = m.wizard.input.Update(msg)
				return m, cmd
			}
		}
		switch msg.String() {
		case "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "esc":
			return m.cancelWizard()
		case "ctrl+p":
			if m.wizard.kind == wizardCreateVPN {
				return m.wizardCreateVPNBack()
			}
		case "up", "k":
			if m.wizard.stepType == stepPicker && m.wizard.pickerIdx > 0 {
				m.wizard.pickerIdx--
			}
		case "down", "j":
			if m.wizard.stepType == stepPicker && m.wizard.pickerIdx < len(m.wizard.picker)-1 {
				m.wizard.pickerIdx++
			}
		case "enter":
			switch m.wizard.stepType {
			case stepPicker:
				return m.wizardPickerEnter()
			case stepConfirm:
				return m.wizardConfirmEnter()
			case stepNotice:
				return m.cancelWizard()
			}
		}
	}
	return m, nil
}
