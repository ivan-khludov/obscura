package tui

import (
	"fmt"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/ivan-khludov/obscura/internal/orchestration"
)

// wizardShowSSTransportPicker switches the wizard to the SSTransportPicker step.
func (m model) wizardShowSSTransportPicker() (model, tea.Cmd) {
	m.wizard.setCreatePickerStep(createStepTransport, "Transport options:", hintTransport, orchestration.ShadowsocksTransportModes(), ssTransportPickerHints())
	m.wizard.pickerIdx = 0
	return m, nil
}

// wizardAcceptSSTransportMode handles a shadowsocks transport mode by name.
func (m model) wizardAcceptSSTransportMode(mode string) (model, tea.Cmd) {
	m.wizard.ssTransport = mode
	m.wizard.ssMultiplex = false
	m.wizard.ssMultiplexPadding = false
	m.wizard.ssShadowTLS = false
	m.wizard.ssPlugin = ""
	m.wizard.ssPluginOpts = ""
	switch mode {
	case "Direct":
		m.wizard.ssMultiplex = false
		m.wizard.ssMultiplexPadding = false
		if next, cmd, ok := m.wizardValidateStep(orchestration.WizardAfterTransport); !ok {
			return next, cmd
		}
		m.wizard.step++
		return m.wizardPrepareClientHostStep()
	case "Multiplex":
		m.wizard.ssMultiplex = true
		if next, cmd, ok := m.wizardValidateStep(orchestration.WizardAfterTransport); !ok {
			return next, cmd
		}
		m.wizard.step++
		return m.wizardPrepareClientHostStep()
	case "Multiplex (padding)":
		m.wizard.ssMultiplex = true
		m.wizard.ssMultiplexPadding = true
		if next, cmd, ok := m.wizardValidateStep(orchestration.WizardAfterTransport); !ok {
			return next, cmd
		}
		m.wizard.step++
		return m.wizardPrepareClientHostStep()
	case "ShadowTLS":
		m.wizard.ssShadowTLS = true
		m.wizard.step++
		m.wizard.setCreateTextStep(
			createStepShadowTLSHandshake,
			fmt.Sprintf("ShadowTLS handshake server [%s]:", orchestration.DefaultShadowsocksHandshake()),
			hintShadowTLS,
			orchestration.DefaultShadowsocksHandshake(),
		)
		return m, textinput.Blink
	default:
		return m, nil
	}
}

// wizardAcceptSSTransport handles wizard input for SSTransport and advances or validates the step.
func (m model) wizardAcceptSSTransport(idx int) (model, tea.Cmd) {
	modes := orchestration.ShadowsocksTransportModes()
	if idx >= len(modes) {
		return m, nil
	}
	return m.wizardAcceptSSTransportMode(modes[idx])
}
