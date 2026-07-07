package tui

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/ivan-khludov/obscura/internal/orchestration"
)

type menuStatusMsg struct {
	bootstrapped bool
}

// loadMenuStatusCmd returns a Bubble Tea command that loads data asynchronously.
func loadMenuStatusCmd(orch *orchestration.Facade) tea.Cmd {
	return func() tea.Msg {
		result, _ := orch.GetBootstrapStatusFromRequest(context.Background(), orchestration.BootstrapStatusRequest{})
		return menuStatusMsg{
			bootstrapped: result.Bootstrapped,
		}
	}
}

// mainMenuItems performs an internal helper operation.
func (m model) mainMenuItems() []string {
	if !m.bootstrapped {
		return []string{"Bootstrap server", "Quit"}
	}
	return []string{"VPNs", "Clients", "System", "Backup / Restore", "Uninstall", "Quit"}
}

// backupMenuItems performs an internal helper operation.
func backupMenuItems() []string {
	return []string{"Create backup", "List backups", "Restore backup", "Back"}
}

// applyMenuStatus applies transport, TLS preview, or option fields to protocol data.
func (m model) applyMenuStatus(msg menuStatusMsg) model {
	m.bootstrapped = msg.bootstrapped
	if m.screen == screenMain {
		m.items = m.mainMenuItems()
		if m.cursor >= len(m.items) {
			m.cursor = 0
		}
	}
	return m
}

// formatBackupList formats output for display or export.
func formatBackupList(entries []orchestration.BackupEntry) string {
	if len(entries) == 0 {
		return "No backups"
	}
	lines := make([]string, len(entries))
	for i, e := range entries {
		lines[i] = fmt.Sprintf("%s  (%s)", e.Name, e.ModTime.UTC().Format("2006-01-02 15:04"))
	}
	return strings.Join(lines, "\n")
}
