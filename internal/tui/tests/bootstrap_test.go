package tui_test

import (
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/tui"
)

func TestBootstrapProgressMsgUpdatesPercent(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetBusy(true)
	m.SetBootstrapCh(make(chan tea.Msg, 1))
	next, cmd := m.Update(tui.NewBootstrapProgressMsgForTest("Downloading sing-box… 42%", 42))
	m2 := next
	if m2.BusyPercent() != 42 {
		t.Fatalf("expected 42%%, got %d", m2.BusyPercent())
	}
	if m2.BusyLabel() != "Downloading sing-box… 42%" {
		t.Fatalf("unexpected label: %q", m2.BusyLabel())
	}
	if cmd == nil {
		t.Fatal("expected follow-up wait cmd")
	}
	panel := m2.RenderPanel()
	if !strings.Contains(panel, "42%") || !strings.Contains(panel, "█") {
		t.Fatalf("expected progress bar in panel, got %q", panel)
	}
}

func TestBootstrapDoneShowsError(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetBusy(true)
	m.SetBootstrapCh(make(chan tea.Msg))
	next, cmd := m.Update(tui.NewBootstrapDoneMsgForTest(errors.New("install sing-box: download timeout")))
	m2 := next
	if m2.Busy() {
		t.Fatal("expected not busy after failure")
	}
	if !strings.Contains(m2.Message(), "Bootstrap failed:") {
		t.Fatalf("unexpected message: %q", m2.Message())
	}
	if !strings.Contains(m2.Message(), "download timeout") {
		t.Fatalf("expected error detail, got %q", m2.Message())
	}
	if cmd == nil {
		t.Fatal("expected menu refresh cmd")
	}
}

func TestProgressBarForTest(t *testing.T) {
	bar := tui.ProgressBarForTest(50, 10)
	if !strings.Contains(bar, "█████") || !strings.Contains(bar, "░░░░░") {
		t.Fatalf("unexpected bar: %q", bar)
	}
	if tui.ProgressBarForTest(-5, 10) != tui.ProgressBarForTest(0, 10) {
		t.Fatal("expected clamp at 0")
	}
	if tui.ProgressBarForTest(150, 10) != tui.ProgressBarForTest(100, 10) {
		t.Fatal("expected clamp at 100")
	}
}

func TestRenderBootstrapProgressForTest(t *testing.T) {
	out := tui.RenderBootstrapProgressForTest("Bootstrapping…", 75)
	if !strings.Contains(out, "75%") || !strings.Contains(out, "Bootstrapping") {
		t.Fatalf("unexpected render: %q", out)
	}
}

func TestWaitBootstrapCmdForTest(t *testing.T) {
	ch := make(chan tea.Msg, 1)
	ch <- tui.NewBootstrapProgressMsgForTest("step", 10)
	close(ch)
	msg := firstTeaMsg(tui.WaitBootstrapCmdForTest(ch))
	if msg == nil {
		t.Fatal("expected message from channel")
	}
	closed := make(chan tea.Msg)
	close(closed)
	if firstTeaMsg(tui.WaitBootstrapCmdForTest(closed)) != nil {
		t.Fatal("expected nil from closed empty channel")
	}
}

func TestStartBootstrapViaHandleSelect(t *testing.T) {
	m, _ := newTestServiceModel(t)
	m.SetItems(m.MainMenuItems())
	m.SetCursor(0)
	done := make(chan struct{}, 1)
	restore := tui.SetBootstrapRunnerForTest(func(_ *orchestration.Facade, ch chan tea.Msg) {
		ch <- tui.NewBootstrapProgressMsgForTest("step 1", 50)
		ch <- tui.NewBootstrapDoneMsgForTest(nil)
		close(ch)
		done <- struct{}{}
	})
	defer restore()

	next, cmd := m.HandleSelect()
	if !next.Busy() || next.BusyPercent() != 0 {
		t.Fatalf("expected busy bootstrap, percent=%d", next.BusyPercent())
	}
	if cmd == nil {
		t.Fatal("expected wait cmd")
	}
	<-done
}

func TestBootstrapDoneSuccess(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetBusy(true)
	m.SetBootstrapCh(make(chan tea.Msg))
	next, cmd := m.Update(tui.NewBootstrapDoneMsgForTest(nil))
	if next.Message() != "Bootstrap complete" {
		t.Fatalf("unexpected message: %q", next.Message())
	}
	if cmd == nil {
		t.Fatal("expected refresh cmd")
	}
}

func TestBootstrapProgressWithoutChannel(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetBusy(true)
	next, cmd := m.Update(tui.NewBootstrapProgressMsgForTest("step", 10))
	if next.BusyPercent() != 10 || cmd != nil {
		t.Fatal("expected progress without wait when no channel")
	}
}

func TestSetBootstrapRunnerForTest(t *testing.T) {
	called := false
	restore := tui.SetBootstrapRunnerForTest(func(_ *orchestration.Facade, ch chan tea.Msg) {
		called = true
		close(ch)
	})
	defer restore()
	m, _ := newTestServiceModel(t)
	m.SetItems(m.MainMenuItems())
	m.SetCursor(0)
	m.HandleSelect()
	if !called {
		t.Fatal("expected custom bootstrap runner")
	}
}
