package tui

import "strings"

// renderPanel renders sing-box configuration fragments for the protocol.
func (m model) renderPanel() string {
	if m.busy {
		if m.busyPercent >= 0 {
			return renderBootstrapProgress(m.busyLabel, m.busyPercent) + "\n"
		}
		return spinnerFrames[m.spin] + " " + m.busyLabel + "\n"
	}
	if m.mode == modeWizard {
		return m.renderWizardPanel()
	}
	if m.message != "" {
		return m.message + "\n"
	}
	return ""
}

// renderWizardPanel renders sing-box configuration fragments for the protocol.
func (m model) renderWizardPanel() string {
	w := m.wizard
	if w.loading {
		return "Loading…\n"
	}
	if w.stepType == stepNotice {
		s := w.notice + "\n"
		if w.notice == "" {
			s = "Loading…\n"
		}
		return s
	}
	var b strings.Builder
	if w.prompt != "" {
		b.WriteString(w.prompt)
		b.WriteByte('\n')
	}
	if hint := w.activeHint(); hint != "" {
		b.WriteString(hintStyle.Render(hint))
		b.WriteByte('\n')
	}
	if w.stepError != "" {
		b.WriteString(w.stepError + "\n")
	}
	switch w.stepType {
	case stepPicker:
		for i, item := range w.picker {
			cursor := "  "
			if i == w.pickerIdx {
				cursor = "> "
			}
			b.WriteString(cursor + item + "\n")
		}
	case stepText:
		b.WriteString(w.input.View())
		b.WriteByte('\n')
	case stepConfirm:
		b.WriteString("Press Enter to confirm, Esc to cancel\n")
	}
	return b.String()
}

// renderHelp renders sing-box configuration fragments for the protocol.
func (m model) renderHelp() string {
	if m.busy {
		return "\nctrl+c abort\n"
	}
	if m.mode == modeWizard {
		help := "\n↑/↓ navigate • enter select/confirm"
		if m.wizard.kind == wizardCreateVPN {
			if m.wizard.stepType == stepText {
				help = "\nctrl+p back • enter confirm • esc cancel"
			} else if m.wizard.stepType == stepPicker {
				help = "\nctrl+p back • ↑/↓ navigate • enter confirm • esc cancel"
			} else {
				help = "\nenter confirm • esc cancel"
			}
		} else if m.wizard.stepType == stepText {
			help = "\nenter confirm • esc cancel"
		} else if m.wizard.stepType == stepNotice && m.wizard.notice != "" {
			help += " • enter/esc cancel"
		} else {
			help += " • esc cancel"
		}
		return help + "\n"
	}
	help := "\n↑/↓ navigate • enter select"
	if m.message != "" {
		help += " • esc dismiss message"
	}
	if m.screen != screenMain {
		help += " • ctrl+b back"
	} else {
		help += " • ctrl+q quit"
	}
	return help + "\n"
}
