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

func (m model) wizardTextEnterCreate(val string) (model, tea.Cmd, bool) {
	if m.wizard.kind != wizardCreateVPN {
		return m, nil, false
	}
	if m.wizard.step == 0 && (m.wizard.createStep == createStepVPNName || m.wizard.prompt == "VPN name:") {
		if val == "" {
			return m, nil, true
		}
		if m.orch != nil {
			if err := m.orch.ValidateVPNNameFromRequest(context.Background(), orchestration.ValidateVPNNameRequest{Name: val}); err != nil {
				m.wizard.basePrompt = "VPN name:"
				next, cmd := m.wizardShowStepError(err)
				return next, cmd, true
			}
		}
		m.wizard.vpnName = val
		next := m
		next.wizard.step++
		next.wizard.loading = true
		next.wizard.stepType = stepNotice
		next.wizard.createStep = createStepProtocol
		next.wizard.notice = ""
		next, cmd, _ := m.wizardAdvanceCreateVPN(next, loadProtocolsCmd(m.orch))
		return next, cmd, true
	}
	if next, cmd, ok := m.wizardCreateVPNTextEnter(val); ok {
		if next.busy {
			return next, cmd, true
		}
		next, cmd, _ = m.wizardAdvanceCreateVPN(next, cmd)
		return next, cmd, true
	}
	return m, nil, false
}

func (m model) wizardTextEnterManage(val string) (model, tea.Cmd, bool) {
	switch m.wizard.kind {
	case wizardAddClient:
		if val == "" {
			return m, nil, true
		}
		m.wizard.clientName = val
		next, cmd := m.wizardFinishAddClient()
		return next, cmd, true
	case wizardSetSSHPort:
		next, cmd := m.wizardAcceptSSHPort(val)
		return next, cmd, true
	case wizardEditVPN:
		if m.wizard.step != 2 {
			return m, nil, true
		}
		switch m.wizard.editField {
		case "Name":
			if val == "" {
				return m, nil, true
			}
			name := val
			next, cmd := m.wizardFinishEditVPN(orchestration.EditVPNRequest{
				VPNName:  m.wizard.vpnName,
				Protocol: m.wizard.selectedVPN.Protocol,
				Update: orchestration.UpdateVPNRequest{
					Name: &name,
				},
				Reapply: true,
			})
			return next, cmd, true
		case "Port":
			port, err := strconv.Atoi(val)
			if err != nil || port <= 0 || port > 65535 {
				m.wizard.prompt = fmt.Sprintf("Port [%d]: (invalid — try again)", m.wizard.selectedVPN.Listen.ListenPort)
				m.wizard.input.SetValue("")
				return m, textinput.Blink, true
			}
			if port == m.configuredSSHPort() {
				m.wizard.prompt = fmt.Sprintf("Port [%d]: (port %d is reserved for SSH; choose another port)", m.wizard.selectedVPN.Listen.ListenPort, port)
				m.wizard.input.SetValue("")
				return m, textinput.Blink, true
			}
			listen := m.wizard.selectedVPN.Listen
			listen.ListenPort = port
			next, cmd := m.wizardFinishEditVPN(orchestration.EditVPNRequest{
				VPNName:  m.wizard.vpnName,
				Protocol: m.wizard.selectedVPN.Protocol,
				Update: orchestration.UpdateVPNRequest{
					Listen: &listen,
				},
				Reapply: true,
			})
			return next, cmd, true
		case "Client host":
			host := strings.TrimSpace(val)
			if host == "" || host == "auto" {
				next, cmd := m.wizardFinishEditVPN(orchestration.EditVPNRequest{
					VPNName:  m.wizard.vpnName,
					Protocol: m.wizard.selectedVPN.Protocol,
					Update: orchestration.UpdateVPNRequest{
						ClearClientHost: true,
					},
					Reapply: true,
				})
				return next, cmd, true
			}
			next, cmd := m.wizardFinishEditVPN(orchestration.EditVPNRequest{
				VPNName:  m.wizard.vpnName,
				Protocol: m.wizard.selectedVPN.Protocol,
				Update: orchestration.UpdateVPNRequest{
					ClientHost: &host,
				},
				Reapply: true,
			})
			return next, cmd, true
		}
	case wizardEditClient:
		if m.wizard.step != 3 {
			return m, nil, true
		}
		if val == "" {
			return m, nil, true
		}
		req := orchestration.UpdateClientRequest{VPNName: m.wizard.vpnName, Name: m.wizard.clientName}
		switch m.wizard.editField {
		case "Name":
			req.NewName = &val
		case "Username":
			req.Username = &val
		case "Password":
			req.Password = &val
		default:
			return m, nil, true
		}
		next, cmd := m.wizardFinishEditClient(req)
		return next, cmd, true
	}
	return m, nil, false
}

func (m model) wizardPickerEnterCreate(idx int) (model, tea.Cmd, bool) {
	if m.wizard.kind != wizardCreateVPN {
		return m, nil, false
	}
	if next, cmd, ok := m.wizardCreateVPNPickerEnter(idx); ok {
		next, cmd, _ = m.wizardAdvanceCreateVPN(next, cmd)
		return next, cmd, true
	}
	return m, nil, true
}

func (m model) wizardPickerEnterManage(idx int) (model, tea.Cmd, bool) {
	switch m.wizard.kind {
	case wizardDeleteVPN:
		if m.wizard.step != 0 || idx >= len(m.wizard.vpns) {
			return m, nil, true
		}
		m.wizard.vpnName = m.wizard.vpns[idx].Name
		m.wizard.step++
		m.wizard.stepType = stepConfirm
		m.wizard.prompt = fmt.Sprintf("Delete VPN %q and all clients?", m.wizard.vpnName)
		return m, nil, true
	case wizardRestoreBackup:
		if m.wizard.step != 0 || idx >= len(m.wizard.backups) {
			return m, nil, true
		}
		m.wizard.backupPath = m.wizard.backups[idx].Path
		m.wizard.step++
		m.wizard.stepType = stepConfirm
		m.wizard.prompt = fmt.Sprintf("Restore from %q?", m.wizard.backups[idx].Name)
		return m, nil, true
	case wizardSetCongestion:
		if idx >= len(m.wizard.congestionOptions) {
			return m, nil, true
		}
		selected := m.wizard.congestionOptions[idx]
		if selected == m.wizard.congestionCurrent {
			m.wizard.stepType = stepNotice
			m.wizard.notice = fmt.Sprintf("%s is already active", selected)
			return m, nil, true
		}
		next, cmd := m.wizardFinishSetCongestion(selected)
		return next, cmd, true
	case wizardAddClient, wizardShowClient, wizardRemoveClient:
		if m.wizard.step == 0 {
			if idx >= len(m.wizard.vpns) {
				return m, nil, true
			}
			m.wizard.vpnName = m.wizard.vpns[idx].Name
			m.wizard.step++
			next, cmd := m.wizardAfterVPNPick()
			return next, cmd, true
		}
		if m.wizard.step == 1 && (m.wizard.kind == wizardShowClient || m.wizard.kind == wizardRemoveClient) {
			if idx >= len(m.wizard.clients) {
				return m, nil, true
			}
			m.wizard.clientName = m.wizard.clients[idx].Name
			m.wizard.step++
			next, cmd := m.wizardAfterClientPick()
			return next, cmd, true
		}
		return m, nil, true
	case wizardEditVPN:
		switch m.wizard.step {
		case 0:
			if idx >= len(m.wizard.vpns) {
				return m, nil, true
			}
			m.wizard.selectedVPN = m.wizard.vpns[idx]
			m.wizard.vpnName = m.wizard.vpns[idx].Name
			m.wizard.step++
			next, cmd := m.wizardShowEditVPNFields()
			return next, cmd, true
		case 1:
			if idx >= len(m.wizard.picker) {
				return m, nil, true
			}
			m.wizard.editField = m.wizard.picker[idx]
			m.wizard.step++
			next, cmd := m.wizardShowEditVPNValue()
			return next, cmd, true
		case 2:
			next, cmd := m.wizardFinishEditVPNFromPicker(idx)
			return next, cmd, true
		}
		return m, nil, true
	case wizardEditClient:
		switch m.wizard.step {
		case 0:
			if idx >= len(m.wizard.vpns) {
				return m, nil, true
			}
			m.wizard.vpnName = m.wizard.vpns[idx].Name
			m.wizard.step++
			next, cmd := m.wizardAfterVPNPick()
			return next, cmd, true
		case 1:
			if idx >= len(m.wizard.clients) {
				return m, nil, true
			}
			m.wizard.selectedClient = m.wizard.clients[idx]
			m.wizard.clientName = m.wizard.clients[idx].Name
			m.wizard.step++
			next, cmd := m.wizardShowEditClientFields()
			return next, cmd, true
		case 2:
			if idx >= len(m.wizard.picker) {
				return m, nil, true
			}
			m.wizard.editField = m.wizard.picker[idx]
			m.wizard.step++
			next, cmd := m.wizardShowEditClientValue()
			return next, cmd, true
		case 3:
			next, cmd := m.wizardFinishEditClientFromPicker(idx)
			return next, cmd, true
		}
		return m, nil, true
	}
	return m, nil, false
}
