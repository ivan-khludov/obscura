package tui

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/ivan-khludov/obscura/internal/orchestration"
)

type bootstrapProgressMsg struct {
	label   string
	percent int
}

type bootstrapDoneMsg struct {
	err error
}

func waitBootstrapCmd(ch <-chan tea.Msg) tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-ch
		if !ok {
			return nil
		}
		return msg
	}
}

type bootstrapRunner func(orch *orchestration.Facade, ch chan tea.Msg)

var bootstrapRunnerFn bootstrapRunner = defaultBootstrapRunner

func defaultBootstrapRunner(orch *orchestration.Facade, ch chan tea.Msg) {
	go func() {
		_, err := orch.BootstrapFromRequest(context.Background(), orchestration.BootstrapRequest{
			Progress: func(p orchestration.BootstrapProgress) {
				ch <- bootstrapProgressMsg{label: p.Label, percent: p.Percent}
			},
		})
		ch <- bootstrapDoneMsg{err: err}
		close(ch)
	}()
}

func (m model) startBootstrap() (model, tea.Cmd) {
	m.busy = true
	m.busyPercent = 0
	m.busyLabel = "Bootstrapping server…"
	m.message = ""

	ch := make(chan tea.Msg, 32)
	m.bootstrapCh = ch
	bootstrapRunnerFn(m.orch, ch)
	return m, waitBootstrapCmd(ch)
}

func progressBar(percent, width int) string {
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	filled := percent * width / 100
	return "[" + strings.Repeat("█", filled) + strings.Repeat("░", width-filled) + "]"
}

func renderBootstrapProgress(label string, percent int) string {
	return fmt.Sprintf("%s\n%s %d%%", label, progressBar(percent, 24), percent)
}
