package tui

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/ivan-khludov/obscura/internal/orchestration"
)

// wizardAcceptWireguardSubnet handles wizard input for WireguardSubnet and advances or validates the step.
func (m model) wizardAcceptWireguardSubnet(val string) (model, tea.Cmd) {
	defaultAddress, _ := orchestration.WireguardDefaults()
	addr := strings.TrimSpace(val)
	if addr == "" {
		addr = defaultAddress
	}
	if _, _, err := net.ParseCIDR(addr); err != nil {
		m.wizard.setPrompt(fmt.Sprintf("Subnet [%s]: (invalid — try again)", defaultAddress), hintWGSubnet)
		m.wizard.input.SetValue("")
		return m, textinput.Blink
	}
	m.wizard.wgAddress = addr
	if next, cmd, ok := m.wizardValidateStep(orchestration.WizardAfterWireguardSubnet); !ok {
		return next, cmd
	}
	m.wizard.step++
	m.wizard.picker = []string{"Direct (userspace)", "System interface"}
	m.wizard.pickerIdx = 0
	m.wizard.setCreatePickerStep(createStepWireguardInterface, "WireGuard interface mode:", hintWGInterface, m.wizard.picker, wgInterfacePickerHints())
	return m, nil
}

// wizardAcceptWireguardSystem handles wizard input for WireguardSystem and advances or validates the step.
func (m model) wizardAcceptWireguardSystem(idx int) (model, tea.Cmd) {
	_, defaultMTU := orchestration.WireguardDefaults()
	m.wizard.wgSystem = idx == 1
	m.wizard.step++
	m.wizard.setCreateTextStep(createStepWireguardMTU, fmt.Sprintf("MTU [%d, empty=default]:", defaultMTU), hintWGMTU, "")
	m.wizard.wgPrompt = "mtu"
	return m, textinput.Blink
}

// wizardAcceptWireguardMTU handles wizard input for WireguardMTU and advances or validates the step.
func (m model) wizardAcceptWireguardMTU(val string) (model, tea.Cmd) {
	_, defaultMTU := orchestration.WireguardDefaults()
	if s := strings.TrimSpace(val); s != "" {
		mtu, err := strconv.Atoi(s)
		if err != nil || mtu < 1280 {
			m.wizard.setPrompt(fmt.Sprintf("MTU [%d, empty=default]: (invalid — try again)", defaultMTU), hintWGMTU)
			m.wizard.input.SetValue("")
			return m, textinput.Blink
		}
		m.wizard.wgMTU = mtu
	}
	if next, cmd, ok := m.wizardValidateStep(orchestration.WizardAfterWireguardMTU); !ok {
		return next, cmd
	}
	m.wizard.wgPrompt = ""
	m.wizard.step++
	return m.wizardPrepareClientHostStep()
}
