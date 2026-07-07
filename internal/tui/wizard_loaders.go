package tui

import (
	"context"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/ivan-khludov/obscura/internal/orchestration"
)

// loadVPNsCmd returns a Bubble Tea command that loads data asynchronously.
func loadVPNsCmd(orch *orchestration.Facade) tea.Cmd {
	return func() tea.Msg {
		result, err := orch.ListVPNsFromRequest(context.Background(), orchestration.ListVPNsRequest{})
		if err != nil {
			return vpnListMsg{err: err}
		}
		return vpnListMsg{vpns: result.Items}
	}
}

// loadClientsCmd returns a Bubble Tea command that loads data asynchronously.
func loadClientsCmd(orch *orchestration.Facade, vpnName string) tea.Cmd {
	return func() tea.Msg {
		result, err := orch.ListClientsFromRequest(context.Background(), orchestration.ListClientsRequest{VPNName: vpnName})
		if err != nil {
			return clientListMsg{err: err}
		}
		return clientListMsg{clients: result.Items}
	}
}

// loadBackupsCmd returns a Bubble Tea command that loads data asynchronously.
func loadBackupsCmd(orch *orchestration.Facade) tea.Cmd {
	return func() tea.Msg {
		result, err := orch.ListBackupsFromRequest(context.Background(), orchestration.ListBackupsRequest{})
		if err != nil {
			return backupListMsg{err: err}
		}
		return backupListMsg{backups: result.Entries}
	}
}

// loadCongestionCmd returns a Bubble Tea command that loads data asynchronously.
func loadCongestionCmd(orch *orchestration.Facade) tea.Cmd {
	return func() tea.Msg {
		result, _ := orch.NetworkCongestionFromRequest(context.Background(), orchestration.NetworkCongestionRequest{})
		return congestionListMsg{algorithms: result.Available, current: result.Current}
	}
}

// loadProtocolsCmd returns a Bubble Tea command that loads data asynchronously.
func loadProtocolsCmd(orch *orchestration.Facade) tea.Cmd {
	return func() tea.Msg {
		result, _ := orch.ListProtocolsFromRequest(context.Background(), orchestration.ProtocolListRequest{})
		return protocolListMsg{protocols: result.Names}
	}
}
