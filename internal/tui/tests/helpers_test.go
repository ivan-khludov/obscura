package tui_test

import (
	"path/filepath"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/ivan-khludov/obscura/internal/config"
	"github.com/ivan-khludov/obscura/internal/firewall"
	"github.com/ivan-khludov/obscura/internal/manifest"
	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/runtime"
	"github.com/ivan-khludov/obscura/internal/service"
	"github.com/ivan-khludov/obscura/internal/singboxcheck"
	"github.com/ivan-khludov/obscura/internal/store"
	"github.com/ivan-khludov/obscura/internal/systemd"
	"github.com/ivan-khludov/obscura/internal/tui"
)

func firstTeaMsg(cmd tea.Cmd) tea.Msg {
	if cmd == nil {
		return nil
	}
	msg := cmd()
	if batch, ok := msg.(tea.BatchMsg); ok {
		var fallback tea.Msg
		for _, c := range batch {
			if c == nil {
				continue
			}
			if m := c(); m != nil {
				if _, ok := m.(tui.CreateVPNResultMsg); ok {
					return m
				}
				if _, ok := m.(tui.ActionDoneMsg); ok {
					return m
				}
				if fallback == nil {
					fallback = m
				}
			}
		}
		return fallback
	}
	return msg
}

func actionDoneFromCmd(cmd tea.Cmd) (tui.ActionDoneMsg, bool) {
	msg := firstTeaMsg(cmd)
	if msg == nil {
		return tui.ActionDoneMsg{}, false
	}
	if batch, ok := msg.(tea.BatchMsg); ok {
		for _, c := range batch {
			if c == nil {
				continue
			}
			if done, ok := c().(tui.ActionDoneMsg); ok {
				return done, true
			}
		}
		return tui.ActionDoneMsg{}, false
	}
	done, ok := msg.(tui.ActionDoneMsg)
	return done, ok
}

func completeAsync(t *testing.T, m *tui.TestModel, cmd tea.Cmd) *tui.TestModel {
	t.Helper()
	done, ok := actionDoneFromCmd(cmd)
	if !ok {
		t.Fatal("expected action done msg from async cmd")
	}
	next, _ := m.Update(done)
	return next
}

func expectClientHostPrompt(t *testing.T, m *tui.TestModel) *tui.TestModel {
	t.Helper()
	if m.Wizard().Prompt != "Client host [auto]:" {
		t.Fatalf("expected client host prompt, got %q", m.Wizard().Prompt)
	}
	m.SetWizardInputValue("")
	next, _ := m.WizardTextEnter()
	if next.Wizard().Prompt != "Client name:" {
		t.Fatalf("expected client name prompt, got %q", next.Wizard().Prompt)
	}
	return next
}

func newTestServiceModel(t *testing.T) (*tui.TestModel, *service.Service) {
	t.Helper()
	dir := t.TempDir()
	app := &config.App{
		DataDir:      dir,
		DBPath:       filepath.Join(dir, "state.db"),
		ConfigPath:   filepath.Join(dir, "sing-box.json"),
		ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode:      true,
	}
	st, err := store.Open(app.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	return tui.NewModelForTest(app, orchestration.New(svc)), svc
}

func closedOrchModel(t *testing.T) *tui.TestModel {
	t.Helper()
	dir := t.TempDir()
	app := &config.App{
		DataDir:      dir,
		DBPath:       filepath.Join(dir, "state.db"),
		ConfigPath:   filepath.Join(dir, "sing-box.json"),
		ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode:      true,
	}
	st, err := store.Open(app.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	orch := orchestration.New(svc)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	return tui.NewModelForTest(app, orch)
}
