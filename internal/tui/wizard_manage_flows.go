package tui

import (
	"context"
	"fmt"
	"strconv"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/ivan-khludov/obscura/internal/orchestration"
)

// wizardAfterVPNPick manages wizard state, validation, or navigation.
func (m model) wizardAfterVPNPick() (model, tea.Cmd) {
	switch m.wizard.kind {
	case wizardAddClient:
		m.wizard.stepType = stepText
		m.wizard.prompt = "Client name:"
		m.wizard.input = newTextInput("phone")
		return m, textinput.Blink
	case wizardShowClient, wizardRemoveClient:
		m.wizard.loading = true
		m.wizard.stepType = stepNotice
		m.wizard.notice = ""
		return m, loadClientsCmd(m.orch, m.wizard.vpnName)
	case wizardDeleteVPN:
		m.wizard.stepType = stepConfirm
		m.wizard.prompt = fmt.Sprintf("Delete VPN %q and all clients?", m.wizard.vpnName)
		return m, nil
	case wizardEditClient:
		m.wizard.loading = true
		m.wizard.stepType = stepNotice
		m.wizard.notice = ""
		return m, loadClientsCmd(m.orch, m.wizard.vpnName)
	}
	return m, nil
}

// wizardAfterClientPick manages wizard state, validation, or navigation.
func (m model) wizardAfterClientPick() (model, tea.Cmd) {
	switch m.wizard.kind {
	case wizardShowClient:
		return m.wizardFinishShowClient()
	case wizardRemoveClient:
		m.wizard.stepType = stepConfirm
		m.wizard.prompt = fmt.Sprintf("Remove client %q from VPN %q?", m.wizard.clientName, m.wizard.vpnName)
		return m, nil
	}
	return m, nil
}

// editVPNFields performs an internal helper operation.
func editVPNFields(vpn orchestration.VPNView) []string {
	fields := []string{"Status", "Name", "Port", "Client host"}
	if vpn.Protocol == "http" {
		fields = append(fields, "TLS")
	}
	return fields
}

// wizardShowEditVPNFields switches the wizard to the EditVPNFields step.
func (m model) wizardShowEditVPNFields() (model, tea.Cmd) {
	m.wizard.picker = editVPNFields(m.wizard.selectedVPN)
	m.wizard.pickerIdx = 0
	m.wizard.stepType = stepPicker
	m.wizard.prompt = "Field to edit:"
	return m, nil
}

// wizardShowEditVPNValue switches the wizard to the EditVPNValue step.
func (m model) wizardShowEditVPNValue() (model, tea.Cmd) {
	vpn := m.wizard.selectedVPN
	switch m.wizard.editField {
	case "Name":
		m.wizard.stepType = stepText
		m.wizard.prompt = fmt.Sprintf("Name [%s]:", vpn.Name)
		m.wizard.input = newTextInput(vpn.Name)
		return m, textinput.Blink
	case "Port":
		m.wizard.stepType = stepText
		m.wizard.prompt = fmt.Sprintf("Port [%d]:", vpn.Listen.ListenPort)
		m.wizard.input = newTextInput(strconv.Itoa(vpn.Listen.ListenPort))
		return m, textinput.Blink
	case "Client host":
		m.wizard.stepType = stepText
		label := vpn.ClientHost
		if label == "" {
			label = "auto"
		}
		m.wizard.prompt = fmt.Sprintf("Client host [%s]:", label)
		m.wizard.input = newTextInput(vpn.ClientHost)
		return m, textinput.Blink
	case "Status":
		m.wizard.stepType = stepPicker
		m.wizard.picker = []string{"Active", "Inactive"}
		m.wizard.pickerIdx = 0
		if !vpn.Enabled {
			m.wizard.pickerIdx = 1
		}
		m.wizard.prompt = "VPN status:"
		return m, nil
	case "TLS":
		tlsEnabled := orchestration.HTTPTLSEnabledFromVPN(vpn)
		m.wizard.stepType = stepPicker
		m.wizard.picker = []string{"Enable TLS", "Disable TLS"}
		m.wizard.pickerIdx = 0
		if !tlsEnabled {
			m.wizard.pickerIdx = 1
		}
		m.wizard.prompt = "TLS:"
		return m, nil
	}
	return m, nil
}

// wizardShowEditClientFields switches the wizard to the EditClientFields step.
func (m model) wizardShowEditClientFields() (model, tea.Cmd) {
	m.wizard.picker = []string{"Status", "Name", "Username", "Password"}
	m.wizard.pickerIdx = 0
	m.wizard.stepType = stepPicker
	m.wizard.prompt = "Field to edit:"
	return m, nil
}

// wizardShowEditClientValue switches the wizard to the EditClientValue step.
func (m model) wizardShowEditClientValue() (model, tea.Cmd) {
	client := m.wizard.selectedClient
	switch m.wizard.editField {
	case "Name":
		m.wizard.stepType = stepText
		m.wizard.prompt = fmt.Sprintf("Name [%s]:", client.Name)
		m.wizard.input = newTextInput(client.Name)
		return m, textinput.Blink
	case "Username":
		m.wizard.stepType = stepText
		m.wizard.prompt = fmt.Sprintf("Username [%s]:", client.Username)
		m.wizard.input = newTextInput(client.Username)
		return m, textinput.Blink
	case "Password":
		m.wizard.stepType = stepText
		m.wizard.prompt = "Password:"
		m.wizard.input = newTextInput("")
		return m, textinput.Blink
	case "Status":
		m.wizard.stepType = stepPicker
		m.wizard.picker = []string{"Active", "Inactive"}
		m.wizard.pickerIdx = 0
		if !client.Enabled {
			m.wizard.pickerIdx = 1
		}
		m.wizard.prompt = "Client status:"
		return m, nil
	}
	return m, nil
}

// wizardFinishEditVPNFromPicker completes the EditVPNFromPicker wizard action.
func (m model) wizardFinishEditVPNFromPicker(idx int) (model, tea.Cmd) {
	switch m.wizard.editField {
	case "Status":
		enabled := idx == 0
		return m.wizardFinishEditVPN(orchestration.EditVPNRequest{
			VPNName:  m.wizard.vpnName,
			Protocol: m.wizard.selectedVPN.Protocol,
			Update: orchestration.UpdateVPNRequest{
				Enabled: &enabled,
			},
			Reapply: true,
		})
	case "TLS":
		enable := idx == 0
		disable := idx != 0
		return m.wizardFinishEditVPN(orchestration.EditVPNRequest{
			VPNName:             m.wizard.vpnName,
			Protocol:            m.wizard.selectedVPN.Protocol,
			TLSEnableRequested:  enable,
			TLSDisableRequested: disable,
			Reapply:             true,
		})
	}
	return m, nil
}

// wizardFinishEditClientFromPicker completes the EditClientFromPicker wizard action.
func (m model) wizardFinishEditClientFromPicker(idx int) (model, tea.Cmd) {
	if m.wizard.editField != "Status" {
		return m, nil
	}
	enabled := idx == 0
	return m.wizardFinishEditClient(orchestration.UpdateClientRequest{
		VPNName: m.wizard.vpnName,
		Name:    m.wizard.clientName,
		Enabled: &enabled,
	})
}

// wizardFinishEditVPN completes the EditVPN wizard action.
func (m model) wizardFinishEditVPN(req orchestration.EditVPNRequest) (model, tea.Cmd) {
	orch := m.orch
	m = m.exitWizardForAction()
	return m.startAsync("Updating VPN…", func() (string, error) {
		result, err := orch.EditVPNFromRequest(context.Background(), req)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Updated VPN %q", result.VPN.Name), nil
	})
}

// wizardFinishEditClient completes the EditClient wizard action.
func (m model) wizardFinishEditClient(req orchestration.UpdateClientRequest) (model, tea.Cmd) {
	orch := m.orch
	m = m.exitWizardForAction()
	return m.startAsync("Updating client…", func() (string, error) {
		req.Reapply = true
		result, err := orch.UpdateClientFromRequest(context.Background(), req)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Updated client %q", result.Client.Name), nil
	})
}

// wizardFinishAddClient completes the AddClient wizard action.
func (m model) wizardFinishAddClient() (model, tea.Cmd) {
	vpnName := m.wizard.vpnName
	clientName := m.wizard.clientName
	orch := m.orch
	m = m.exitWizardForAction()
	return m.startAsync("Adding client…", func() (string, error) {
		added, err := orch.AddClientFromRequest(context.Background(), orchestration.AddClientRequest{
			VPNName: vpnName,
			Name:    clientName,
			Reapply: true,
		})
		if err != nil {
			return "", err
		}
		text := added.URI
		if export, err := orch.ShowClientFromRequest(context.Background(), orchestration.ShowClientRequest{
			VPNName:         vpnName,
			Name:            clientName,
			IncludeQR:       true,
			AllowQRFallback: true,
		}); err == nil {
			if formatted, err := formatClientExport(added.URI, export.QRContent); err == nil {
				text = formatted
			}
		}
		return text, nil
	})
}

// wizardFinishShowClient completes the ShowClient wizard action.
func (m model) wizardFinishShowClient() (model, tea.Cmd) {
	vpnName := m.wizard.vpnName
	clientName := m.wizard.clientName
	orch := m.orch
	m = m.exitWizardForAction()
	return m.startAsync("Loading client URI…", func() (string, error) {
		export, err := orch.ShowClientFromRequest(context.Background(), orchestration.ShowClientRequest{
			VPNName:         vpnName,
			Name:            clientName,
			IncludeQR:       true,
			AllowQRFallback: true,
		})
		if err != nil {
			return "", err
		}
		return formatClientExport(export.URI, export.QRContent)
	})
}

// wizardFinishRemoveClient completes the RemoveClient wizard action.
func (m model) wizardFinishRemoveClient() (model, tea.Cmd) {
	vpnName := m.wizard.vpnName
	clientName := m.wizard.clientName
	orch := m.orch
	m = m.exitWizardForAction()
	return m.startAsync("Removing client…", func() (string, error) {
		if _, err := orch.RemoveClientFromRequest(context.Background(), orchestration.RemoveClientRequest{VPNName: vpnName, Name: clientName}); err != nil {
			return "", err
		}
		return fmt.Sprintf("Removed client %q from VPN %q", clientName, vpnName), nil
	})
}

// wizardFinishDeleteVPN completes the DeleteVPN wizard action.
func (m model) wizardFinishDeleteVPN() (model, tea.Cmd) {
	name := m.wizard.vpnName
	orch := m.orch
	m = m.exitWizardForAction()
	return m.startAsync("Deleting VPN…", func() (string, error) {
		if _, err := orch.DeleteVPNFromRequest(context.Background(), orchestration.DeleteVPNRequest{Name: name}); err != nil {
			return "", err
		}
		return fmt.Sprintf("Deleted VPN %q", name), nil
	})
}

// exitWizardForAction exits or cancels the current wizard or screen.
func (m model) exitWizardForAction() model {
	m.mode = modeMenu
	m.wizard = wizardState{}
	return m
}
