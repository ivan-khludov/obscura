// Package tui provides the interactive terminal menu for obscura.
package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ivan-khludov/obscura/internal/config"
	"github.com/ivan-khludov/obscura/internal/doctor"
	"github.com/ivan-khludov/obscura/internal/orchestration"
)

// titleStyle formats the TUI header text.
var titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("69"))

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

const (
	enterDebounce = 50 * time.Millisecond
	panelSep      = "────────────────────────"
)

func defaultIsTTY(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

var isTTYFn = defaultIsTTY

// IsTTY reports whether f is a terminal device.
func IsTTY(f *os.File) bool {
	return isTTYFn(f)
}

type screen int

const (
	screenMain screen = iota
	screenVPNs
	screenClients
	screenSystem
	screenBackup
)

type model struct {
	orch         *orchestration.Facade
	app          *config.App
	screen       screen
	items        []string
	cursor       int
	frozenCursor int
	mode         uiMode
	wizard       wizardState
	message      string
	busy         bool
	busyLabel    string
	busyPercent  int
	bootstrapCh  chan tea.Msg
	spin         int
	ignoreEnter  bool
	bootstrapped bool
	quitting     bool
}

type tickMsg struct{}

type clearIgnoreEnterMsg struct{}

type actionDoneMsg struct {
	text        string
	runErr      error
	refreshMenu bool
}

// newModel returns the initial Bubble Tea model for the root menu.
func newModel(app *config.App, orch ...*orchestration.Facade) model {
	var facade *orchestration.Facade
	if len(orch) > 0 {
		facade = orch[0]
	}
	m := model{
		orch:        facade,
		app:         app,
		screen:      screenMain,
		mode:        modeMenu,
		busyPercent: -1,
	}
	m.items = m.mainMenuItems()
	return m
}

// vpnMenuItems returns VPN submenu entries.
func vpnMenuItems() []string {
	return []string{"Create VPN", "List VPNs", "Edit VPN", "Delete VPN", "Back"}
}

// clientMenuItems returns client submenu entries.
func clientMenuItems() []string {
	return []string{"Add client", "Edit client", "Show client URI", "Remove client", "Back"}
}

// systemMenuItems returns system submenu entries.
func systemMenuItems() []string {
	return []string{"Status", "Doctor", "TCP congestion", "SSH port", "Apply configuration", "Back"}
}

// Init implements tea.Model and loads bootstrap menu state.
func (m model) Init() tea.Cmd {
	return loadMenuStatusCmd(m.orch)
}

// Update implements tea.Model and handles keyboard input and menu actions.
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case menuStatusMsg:
		m = m.applyMenuStatus(msg)
		return m, nil

	case tickMsg:
		if !m.busy {
			return m, nil
		}
		m.spin = (m.spin + 1) % len(spinnerFrames)
		return m, tickCmd()

	case clearIgnoreEnterMsg:
		m.ignoreEnter = false
		return m, nil

	case createVPNResultMsg:
		m.busy = false
		m.busyLabel = ""
		if m.mode == modeWizard {
			return m.applyCreateVPNResult(msg)
		}
		return m, nil

	case sshPortSetMsg:
		if m.mode == modeWizard {
			return m.applySSHPortSet(msg)
		}
		return m, nil

	case actionDoneMsg:
		m.busy = false
		m.busyLabel = ""
		m.busyPercent = -1
		m.ignoreEnter = true
		if msg.runErr != nil {
			m.message = msg.runErr.Error()
		} else {
			m.message = msg.text
		}
		cmds := []tea.Cmd{clearIgnoreEnterCmd()}
		if msg.refreshMenu {
			cmds = append(cmds, loadMenuStatusCmd(m.orch))
		}
		return m, tea.Batch(cmds...)

	case bootstrapProgressMsg:
		m.busyLabel = msg.label
		m.busyPercent = msg.percent
		if m.bootstrapCh != nil {
			return m, waitBootstrapCmd(m.bootstrapCh)
		}
		return m, nil

	case bootstrapDoneMsg:
		m.bootstrapCh = nil
		m.busy = false
		m.busyLabel = ""
		m.busyPercent = -1
		m.ignoreEnter = true
		if msg.err != nil {
			m.message = "Bootstrap failed:\n" + msg.err.Error()
		} else {
			m.message = "Bootstrap complete"
		}
		return m, tea.Batch(clearIgnoreEnterCmd(), loadMenuStatusCmd(m.orch))

	case vpnListMsg, clientListMsg, backupListMsg, protocolListMsg, congestionListMsg:
		if m.mode == modeWizard {
			return m.updateWizard(msg)
		}
		return m, nil

	case tea.KeyMsg:
		if m.busy {
			if msg.String() == "ctrl+c" {
				m.quitting = true
				return m, tea.Quit
			}
			return m, nil
		}
		if m.mode == modeWizard {
			return m.updateWizard(msg)
		}
		switch msg.String() {
		case "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "ctrl+q":
			if m.screen == screenMain {
				m.quitting = true
				return m, tea.Quit
			}
		case "ctrl+b":
			if m.screen != screenMain {
				return m.goBackMain()
			}
		case "esc":
			if m.message != "" {
				m.message = ""
				return m, nil
			}
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.items)-1 {
				m.cursor++
			}
		case "enter":
			if m.ignoreEnter {
				return m, nil
			}
			return m.handleSelect()
		}
	}
	return m, nil
}

// tickCmd returns a Bubble Tea command for async work.
func tickCmd() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(_ time.Time) tea.Msg { return tickMsg{} })
}

// clearIgnoreEnterCmd returns a Bubble Tea command for async work.
func clearIgnoreEnterCmd() tea.Cmd {
	return tea.Tick(enterDebounce, func(_ time.Time) tea.Msg { return clearIgnoreEnterMsg{} })
}

// debounceEnter performs an internal helper operation.
func (m model) debounceEnter() (model, tea.Cmd) {
	m.ignoreEnter = true
	return m, clearIgnoreEnterCmd()
}

// openSubmenu updates firewall rules for a listen port.
func (m model) openSubmenu(s screen, items []string) (model, tea.Cmd) {
	m.screen = s
	m.items = items
	m.cursor = 0
	m.message = ""
	return m.debounceEnter()
}

// goBackMain performs an internal helper operation.
func (m model) goBackMain() (model, tea.Cmd) {
	m.screen = screenMain
	m.items = m.mainMenuItems()
	m.cursor = 0
	m.message = ""
	return m.debounceEnter()
}

// startAsync starts a wizard or async operation.
func (m model) startAsync(label string, fn func() (string, error)) (model, tea.Cmd) {
	return m.startAsyncOpts(label, fn, false)
}

// startAsyncRefresh starts a wizard or async operation.
func (m model) startAsyncRefresh(label string, fn func() (string, error)) (model, tea.Cmd) {
	return m.startAsyncOpts(label, fn, true)
}

// startAsyncOpts starts a wizard or async operation.
func (m model) startAsyncOpts(label string, fn func() (string, error), refreshMenu bool) (model, tea.Cmd) {
	m.busy = true
	m.busyLabel = label
	m.message = ""
	return m, tea.Batch(tickCmd(), func() tea.Msg {
		text, err := fn()
		return actionDoneMsg{text: text, runErr: err, refreshMenu: refreshMenu}
	})
}

// handleSelect executes the menu item at the current cursor position.
func (m model) handleSelect() (model, tea.Cmd) {
	ctx := context.Background()
	switch m.screen {
	case screenMain:
		switch m.items[m.cursor] {
		case "Bootstrap server":
			return m.startBootstrap()
		case "VPNs":
			return m.openSubmenu(screenVPNs, vpnMenuItems())
		case "Clients":
			return m.openSubmenu(screenClients, clientMenuItems())
		case "System":
			return m.openSubmenu(screenSystem, systemMenuItems())
		case "Backup / Restore":
			return m.openSubmenu(screenBackup, backupMenuItems())
		case "Uninstall":
			m.message = "Run: obscura uninstall --dry-run"
		case "Quit":
			m.quitting = true
			return m, tea.Quit
		}
	case screenBackup:
		switch m.items[m.cursor] {
		case "Create backup":
			orch := m.orch
			return m.startAsync("Creating backup…", func() (string, error) {
				result, err := orch.CreateBackupFromRequest(ctx, orchestration.CreateBackupRequest{})
				if err != nil {
					return "", err
				}
				return "New backup: " + filepath.Base(result.Path), nil
			})
		case "List backups":
			orch := m.orch
			return m.startAsync("Loading backups…", func() (string, error) {
				result, err := orch.ListBackupsFromRequest(ctx, orchestration.ListBackupsRequest{})
				if err != nil {
					return "", err
				}
				return formatBackupList(result.Entries), nil
			})
		case "Restore backup":
			return m.startRestoreBackupWizard()
		case "Back":
			return m.goBackMain()
		}
	case screenVPNs:
		switch m.items[m.cursor] {
		case "Create VPN":
			return m.startWizard(wizardCreateVPN)
		case "List VPNs":
			orch := m.orch
			return m.startAsync("Loading VPNs…", func() (string, error) {
				result, err := orch.ListVPNsFromRequest(ctx, orchestration.ListVPNsRequest{})
				if err != nil {
					return "", err
				}
				vpns := result.Items
				if len(vpns) == 0 {
					return "No VPNs", nil
				}
				names := make([]string, len(vpns))
				for i, v := range vpns {
					names[i] = vpnLabel(v)
				}
				return strings.Join(names, "\n"), nil
			})
		case "Edit VPN":
			return m.startWizard(wizardEditVPN)
		case "Delete VPN":
			return m.startWizard(wizardDeleteVPN)
		case "Back":
			return m.goBackMain()
		}
	case screenClients:
		switch m.items[m.cursor] {
		case "Add client":
			return m.startWizard(wizardAddClient)
		case "Edit client":
			return m.startWizard(wizardEditClient)
		case "Show client URI":
			return m.startWizard(wizardShowClient)
		case "Remove client":
			return m.startWizard(wizardRemoveClient)
		case "Back":
			return m.goBackMain()
		}
	case screenSystem:
		switch m.items[m.cursor] {
		case "Status":
			orch := m.orch
			return m.startAsync("Loading status…", func() (string, error) {
				st, err := orch.StatusFromRequest(ctx, orchestration.StatusRequest{})
				if err != nil {
					return "", err
				}
				return fmt.Sprintf("VPNs: %d, clients: %d, sing-box active: %v, TCP congestion: %s, SSH port: %d",
					st.VPNCount, st.ClientCount, st.SingBoxActive, st.CongestionControl, st.SSHPort), nil
			})
		case "Doctor":
			orch := m.orch
			return m.startAsync("Running doctor…", func() (string, error) {
				results, _ := orch.DoctorFromRequest(ctx, orchestration.DoctorRequest{})
				lines := make([]string, len(results))
				for i, r := range results {
					lines[i] = fmt.Sprintf("[%s] %s: %s", r.Status, r.Name, r.Message)
				}
				text := strings.Join(lines, "\n")
				if doctor.HasFailures(results) {
					text += "\n(doctor found failures)"
				}
				return text, nil
			})
		case "TCP congestion":
			return m.startCongestionWizard()
		case "SSH port":
			return m.startSSHPortWizard()
		case "Apply configuration":
			orch := m.orch
			return m.startAsync("Applying configuration…", func() (string, error) {
				if _, err := orch.ApplyFromRequest(ctx, orchestration.ApplyRequest{DryRun: false}); err != nil {
					return "", err
				}
				return "Configuration applied", nil
			})
		case "Back":
			return m.goBackMain()
		}
	}
	return m, nil
}

// View implements tea.Model and renders the current menu screen.
func (m model) View() string {
	if m.quitting {
		return ""
	}
	title := "obscura"
	switch m.screen {
	case screenVPNs:
		title = "obscura / VPNs"
	case screenClients:
		title = "obscura / Clients"
	case screenSystem:
		title = "obscura / System"
	case screenBackup:
		title = "obscura / Backup"
	}

	menuCursor := m.cursor
	if m.mode == modeWizard {
		menuCursor = m.frozenCursor
	}

	var b strings.Builder
	b.WriteString(titleStyle.Render(title))
	b.WriteString("\n\n")
	for i, item := range m.items {
		cursor := "  "
		if i == menuCursor {
			cursor = "> "
		}
		b.WriteString(cursor + item + "\n")
	}

	panel := strings.TrimRight(m.renderPanel(), "\n")
	if panel != "" {
		b.WriteString("\n")
		b.WriteString(panelSep)
		b.WriteString("\n")
		b.WriteString(panel)
		b.WriteByte('\n')
	}

	b.WriteString(m.renderHelp())
	return b.String()
}

type programRunner interface {
	Run() (tea.Model, error)
}

type programFactoryType func(tea.Model, ...tea.ProgramOption) programRunner

var programFactory programFactoryType = func(m tea.Model, opts ...tea.ProgramOption) programRunner {
	return tea.NewProgram(m, opts...)
}

// Run starts the interactive TUI main menu.
func Run(ctx context.Context, orch *orchestration.Facade, app *config.App) error {
	_ = ctx
	_, err := programFactory(newModel(app, orch), tea.WithAltScreen()).Run()
	return err
}
