package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/ivan-khludov/obscura/internal/orchestration"
)

// wizardShowTuicCongestionPicker switches the wizard to the TuicCongestionPicker step.
func (m model) wizardShowTuicCongestionPicker() (model, tea.Cmd) {
	m.wizard.picker = orchestration.TUICCongestionPickerModes()
	m.wizard.pickerIdx = 0
	m.wizard.setCreatePickerStep(createStepTUICCongestion, "Congestion control:", hintTuicCC, m.wizard.picker, tuicCongestionPickerHints())
	return m, nil
}

// wizardAcceptTuicSNI handles wizard input for TuicSNI and advances or validates the step.
func (m model) wizardAcceptTuicSNI(val string) (model, tea.Cmd) {
	m.wizard.tuicServerName = val
	if next, cmd, ok := m.wizardValidateStep(orchestration.WizardAfterSNI); !ok {
		return next, cmd
	}
	m.wizard.step++
	return m.wizardShowTuicCongestionPicker()
}

// wizardAcceptTuicCongestion handles wizard input for TuicCongestion and advances or validates the step.
func (m model) wizardAcceptTuicCongestion(idx int) (model, tea.Cmd) {
	m.wizard.tuicCongestionControl = orchestration.TUICCongestionByIndex(idx)
	m.wizard.step++
	m.wizard.picker = []string{"Disabled (recommended)", "Enabled (replay risk)"}
	m.wizard.pickerIdx = 0
	m.wizard.setCreatePickerStep(createStepTUICZeroRTT, "0-RTT handshake:", hintTuicZeroRTT, m.wizard.picker, tuicZeroRTTPickerHints())
	return m, nil
}

// wizardAcceptTuicZeroRTT handles wizard input for TuicZeroRTT and advances or validates the step.
func (m model) wizardAcceptTuicZeroRTT(idx int) (model, tea.Cmd) {
	m.wizard.tuicZeroRTT = idx == 1
	m.wizard.step++
	m.wizard.stepType = stepText
	return m.wizardPrepareClientHostStep()
}
