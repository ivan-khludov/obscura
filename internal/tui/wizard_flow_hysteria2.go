package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/ivan-khludov/obscura/internal/orchestration"
)

// wizardShowHy2BandwidthPicker switches the wizard to the Hy2BandwidthPicker step.
func (m model) wizardShowHy2BandwidthPicker() (model, tea.Cmd) {
	m.wizard.picker = []string{"No limit", "Set bandwidth", "Ignore client bandwidth (BBR)"}
	m.wizard.pickerIdx = 0
	m.wizard.setCreatePickerStep(createStepHy2Bandwidth, "Bandwidth:", hintHy2Bandwidth, m.wizard.picker, hy2BandwidthPickerHints())
	return m, nil
}

// wizardAcceptHy2SNI handles wizard input for Hy2SNI and advances or validates the step.
func (m model) wizardAcceptHy2SNI(val string) (model, tea.Cmd) {
	m.wizard.hy2ServerName = val
	if next, cmd, ok := m.wizardValidateStep(orchestration.WizardAfterSNI); !ok {
		return next, cmd
	}
	m.wizard.step++
	return m.wizardShowHy2BandwidthPicker()
}

// wizardAcceptHy2Bandwidth handles wizard input for Hy2Bandwidth and advances or validates the step.
func (m model) wizardAcceptHy2Bandwidth(idx int) (model, tea.Cmd) {
	switch idx {
	case 0:
		m.wizard.hy2UpMbps = 0
		m.wizard.hy2DownMbps = 0
		m.wizard.hy2IgnoreBW = false
	case 1:
		m.wizard.step++
		m.wizard.hy2PendingPrompt = "up_mbps"
		m.wizard.setCreateTextStep(createStepHy2BandwidthUp, "Upload bandwidth (Mbps) [100]:", hintHy2UpMbps, "100")
		return m, textinput.Blink
	case 2:
		m.wizard.hy2IgnoreBW = true
	default:
		return m, nil
	}
	if next, cmd, ok := m.wizardValidateStep(orchestration.WizardAfterHy2Bandwidth); !ok {
		return next, cmd
	}
	m.wizard.step++
	return m.wizardShowHy2ObfsPicker()
}

// wizardShowHy2ObfsPicker switches the wizard to the Hy2ObfsPicker step.
func (m model) wizardShowHy2ObfsPicker() (model, tea.Cmd) {
	m.wizard.picker = []string{"None", "Salamander"}
	m.wizard.pickerIdx = 0
	m.wizard.setCreatePickerStep(createStepHy2Obfs, "Obfuscation:", hintHy2Obfs, m.wizard.picker, hy2ObfsPickerHints())
	return m, nil
}

// wizardAcceptHy2Obfs handles wizard input for Hy2Obfs and advances or validates the step.
func (m model) wizardAcceptHy2Obfs(idx int) (model, tea.Cmd) {
	if idx == 1 {
		m.wizard.hy2ObfsPassword = "auto"
	}
	m.wizard.step++
	return m.wizardShowHy2MasqueradePicker()
}

// wizardShowHy2MasqueradePicker switches the wizard to the Hy2MasqueradePicker step.
func (m model) wizardShowHy2MasqueradePicker() (model, tea.Cmd) {
	m.wizard.picker = []string{"None", "Reverse proxy URL", "File directory"}
	m.wizard.pickerIdx = 0
	m.wizard.setCreatePickerStep(createStepHy2Masquerade, "Masquerade:", hintHy2Masquerade, m.wizard.picker, hy2MasqueradePickerHints())
	return m, nil
}

// wizardAcceptHy2Masquerade handles wizard input for Hy2Masquerade and advances or validates the step.
func (m model) wizardAcceptHy2Masquerade(idx int) (model, tea.Cmd) {
	switch idx {
	case 0:
		m.wizard.hy2MasqueradeURL = ""
	case 1:
		m.wizard.step++
		m.wizard.hy2PendingPrompt = "masquerade_proxy"
		m.wizard.setCreateTextStep(createStepHy2MasqueradeProxy, "Masquerade proxy URL [http://127.0.0.1:8080]:", hintHy2MasqProxy, "http://127.0.0.1:8080")
		return m, textinput.Blink
	case 2:
		m.wizard.step++
		m.wizard.hy2PendingPrompt = "masquerade_file"
		m.wizard.setCreateTextStep(createStepHy2MasqueradeFile, "Masquerade file directory [/var/www]:", hintHy2MasqFile, "/var/www")
		return m, textinput.Blink
	default:
		return m, nil
	}
	if next, cmd, ok := m.wizardValidateStep(orchestration.WizardAfterHy2Masquerade); !ok {
		return next, cmd
	}
	m.wizard.step++
	return m.wizardPrepareClientHostStep()
}

// wizardAcceptHy2MasqueradeDetail handles wizard input for Hy2MasqueradeDetail and advances or validates the step.
func (m model) wizardAcceptHy2MasqueradeDetail(val string) (model, tea.Cmd) {
	switch m.wizard.hy2PendingPrompt {
	case "masquerade_proxy":
		url := strings.TrimSpace(val)
		if url == "" {
			url = "http://127.0.0.1:8080"
		}
		m.wizard.hy2MasqueradeURL = url
	case "masquerade_file":
		dir := strings.TrimSpace(val)
		if dir == "" {
			dir = "/var/www"
		}
		m.wizard.hy2MasqueradeURL = "file://" + dir
	}
	m.wizard.hy2PendingPrompt = ""
	if next, cmd, ok := m.wizardValidateStep(orchestration.WizardAfterHy2Masquerade); !ok {
		return next, cmd
	}
	m.wizard.step++
	return m.wizardPrepareClientHostStep()
}

// wizardAcceptHy2BandwidthDetail handles wizard input for Hy2BandwidthDetail and advances or validates the step.
func (m model) wizardAcceptHy2BandwidthDetail(val string) (model, tea.Cmd) {
	switch m.wizard.hy2PendingPrompt {
	case "up_mbps":
		up := 100
		if s := strings.TrimSpace(val); s != "" {
			p, err := strconv.Atoi(s)
			if err != nil || p <= 0 {
				m.wizard.setPrompt("Upload bandwidth (Mbps) [100]: (invalid — try again)", hintHy2UpMbps)
				m.wizard.input.SetValue("")
				return m, textinput.Blink
			}
			up = p
		}
		m.wizard.hy2UpMbps = up
		m.wizard.hy2PendingPrompt = "down_mbps"
		m.wizard.setPrompt(fmt.Sprintf("Download bandwidth (Mbps) [%d]:", up), hintHy2DownMbps)
		m.wizard.input = newTextInput(strconv.Itoa(up))
		return m, textinput.Blink
	case "down_mbps":
		down := m.wizard.hy2UpMbps
		if down == 0 {
			down = 100
		}
		if s := strings.TrimSpace(val); s != "" {
			p, err := strconv.Atoi(s)
			if err != nil || p <= 0 {
				m.wizard.setPrompt(fmt.Sprintf("Download bandwidth (Mbps) [%d]: (invalid — try again)", down), hintHy2DownMbps)
				m.wizard.input.SetValue("")
				return m, textinput.Blink
			}
			down = p
		}
		m.wizard.hy2DownMbps = down
		m.wizard.hy2PendingPrompt = ""
		if next, cmd, ok := m.wizardValidateStep(orchestration.WizardAfterHy2Bandwidth); !ok {
			return next, cmd
		}
		m.wizard.step++
		return m.wizardShowHy2ObfsPicker()
	}
	return m, nil
}
