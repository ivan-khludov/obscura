package tui_test

import (
	"context"
	"errors"
	"os"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/ivan-khludov/obscura/internal/config"
	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/tui"
)

func TestEnterDebounceAfterSubmenu(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetBootstrapped(true)
	m.SetItems(m.MainMenuItems())
	m.SetCursor(0) // VPNs.
	next, cmd := m.HandleSelect()
	m2 := next
	if m2.Screen() != tui.ScreenVPNs {
		t.Fatalf("expected VPNs screen, got %d", m2.Screen())
	}
	if !m2.IgnoreEnter() {
		t.Fatal("expected ignoreEnter after submenu open")
	}
	if cmd == nil {
		t.Fatal("expected debounce cmd")
	}

	afterEnter, _ := m2.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m3 := afterEnter
	if m3.Screen() != tui.ScreenVPNs || !m3.IgnoreEnter() {
		t.Fatal("enter should be ignored while debouncing")
	}

	afterClear, _ := m3.Update(tui.ClearIgnoreEnterMsg{})
	m4 := afterClear
	if m4.IgnoreEnter() {
		t.Fatal("expected ignoreEnter cleared")
	}
}

func TestEscDismissesMessage(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMessage("Bootstrap complete")
	m.SetScreen(tui.ScreenMain)

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m2 := next
	if m2.Message() != "" {
		t.Fatal("expected message cleared by esc")
	}
}

// TestEnterDoesNotDismissMessage verifies Enter no longer clears messages without selecting an action.

func TestEnterDoesNotDismissMessage(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetBootstrapped(true)
	m.SetItems(m.MainMenuItems())
	m.SetMessage("Bootstrap complete")
	m.SetCursor(len(m.Items()) - 2) // Uninstall.

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := next
	if m2.Message() == "" {
		t.Fatal("enter must not dismiss message")
	}
}

// TestActionDoneShowsSuccessText verifies business success is shown even when exec restore runs.

func TestActionDoneShowsSuccessText(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetBusy(true)

	next, cmd := m.Update(tui.NewActionDoneMsgForTest("Bootstrap complete", nil, false))
	m2 := next
	if m2.Message() != "Bootstrap complete" {
		t.Fatalf("unexpected message: %q", m2.Message())
	}
	if m2.Busy() {
		t.Fatal("expected not busy")
	}
	if !m2.IgnoreEnter() {
		t.Fatal("expected enter debounce after action")
	}
	if cmd == nil {
		t.Fatal("expected follow-up cmd")
	}
}

// TestNavigationAfterAction verifies arrow keys work after an action completes.

func TestNavigationAfterAction(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetBusy(true)

	afterDone, _ := m.Update(tui.NewActionDoneMsgForTest("Bootstrap complete", nil, false))
	m2 := afterDone
	afterClear, _ := m2.Update(tui.ClearIgnoreEnterMsg{})
	m3 := afterClear
	afterDown, _ := m3.Update(tea.KeyMsg{Type: tea.KeyDown})
	m4 := afterDown
	if m4.Cursor() != 1 {
		t.Fatalf("expected cursor 1 after down, got %d", m4.Cursor())
	}
	if m4.Message() != "Bootstrap complete" {
		t.Fatal("message should persist while navigating")
	}
}

// TestCtrlBReturnsToMain verifies ctrl+b navigates back from a submenu.

func TestCtrlBReturnsToMain(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetBootstrapped(true)
	m.SetItems(m.MainMenuItems())
	m.SetCursor(0)
	next, _ := m.HandleSelect()
	mVPN := next

	back, _ := mVPN.Update(tea.KeyMsg{Type: tea.KeyCtrlB})
	mMain := back
	if mMain.Screen() != tui.ScreenMain {
		t.Fatalf("expected main screen, got %d", mMain.Screen())
	}
}

// TestActionDoneShowsRunError verifies run errors are displayed.

func TestActionDoneShowsRunError(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetBusy(true)
	errTest := errors.New("bootstrap failed")

	next, _ := m.Update(tui.NewActionDoneMsgForTest("", errTest, false))
	m2 := next
	if m2.Message() != "bootstrap failed" {
		t.Fatalf("unexpected message: %q", m2.Message())
	}
}

// TestEscCancelsWizard verifies Esc exits wizard mode.

func TestMainMenuBeforeBootstrap(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	items := m.MainMenuItems()
	if len(items) != 2 || items[0] != "Bootstrap server" || items[1] != "Quit" {
		t.Fatalf("unexpected pre-bootstrap menu: %#v", items)
	}
}

// TestMainMenuAfterBootstrap hides bootstrap when server is bootstrapped.

func TestMainMenuAfterBootstrap(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetBootstrapped(true)
	items := m.MainMenuItems()
	for _, item := range items {
		if item == "Bootstrap server" {
			t.Fatalf("unexpected item %q in post-bootstrap menu", item)
		}
	}
	want := []string{"VPNs", "Clients", "System", "Backup / Restore", "Uninstall", "Quit"}
	if len(items) != len(want) {
		t.Fatalf("unexpected menu length: got %d want %d (%#v)", len(items), len(want), items)
	}
	for i, item := range want {
		if items[i] != item {
			t.Fatalf("unexpected menu: got %#v want %#v", items, want)
		}
	}
}

// TestBackupSubmenuItems verifies backup submenu entries.

func TestMenuStatusMsgRebuildsMainMenu(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	next, _ := m.Update(tui.NewMenuStatusMsgForTest(true))
	m2 := next
	if !m2.Bootstrapped() {
		t.Fatal("expected bootstrapped")
	}
	if len(m2.Items()) < 3 || m2.Items()[0] != "VPNs" {
		t.Fatalf("unexpected menu after status: %#v", m2.Items())
	}
}

// TestCreateVPNWizardTrojanPortDefault verifies trojan default port is 443.

func TestInitLoadsMenuStatus(t *testing.T) {
	m, svc := newTestServiceModel(t)
	cmd := m.Init()
	if cmd == nil {
		t.Fatal("expected init cmd")
	}
	msg := firstTeaMsg(cmd)
	if msg == nil {
		t.Fatal("expected menu status msg")
	}
	_ = svc
}

func TestIsTTYForTest(t *testing.T) {
	restore := tui.SetIsTTYForTest(func(_ *os.File) bool { return true })
	defer restore()
	if !tui.IsTTYForTest(nil) {
		t.Fatal("expected mocked tty true")
	}
}

func TestRunForTest(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{DataDir: dir, DevMode: true}
	m, svc := newTestServiceModel(t)
	orch := orchestration.New(svc)
	called := false
	restore := tui.SetProgramFactoryStubForTest(func(model tea.Model) (tea.Model, error) {
		called = true
		return model, nil
	})
	defer restore()
	if err := tui.RunForTest(context.Background(), orch, app); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("expected program factory called")
	}
	_ = m
}

func TestCtrlCQuits(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if !next.Quitting() || cmd == nil {
		t.Fatal("expected quit on ctrl+c")
	}
}

func TestCtrlQQuitsOnMain(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetScreen(tui.ScreenMain)
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlQ})
	if !next.Quitting() || cmd == nil {
		t.Fatal("expected quit on ctrl+q")
	}
}

func TestBusyCtrlCQuits(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetBusy(true)
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if !next.Quitting() || cmd == nil {
		t.Fatal("expected quit while busy")
	}
}

func TestHandleSelectVPNSubmenu(t *testing.T) {
	m, _ := newTestServiceModel(t)
	m.SetBootstrapped(true)
	m.SetItems(m.MainMenuItems())
	m.SetCursor(0) // VPNs.
	next, _ := m.HandleSelect()
	if next.Screen() != tui.ScreenVPNs {
		t.Fatal("expected VPNs screen")
	}

	m2 := next
	m2.SetCursor(1) // List VPNs.
	next2, cmd := m2.HandleSelect()
	if !next2.Busy() || cmd == nil {
		t.Fatal("expected busy list vpns")
	}

	m3 := next
	m3.SetCursor(0) // Create VPN.
	next3, _ := m3.HandleSelect()
	if next3.Mode() != tui.ModeWizard {
		t.Fatal("expected wizard mode")
	}
}

func TestHandleSelectClientsSubmenu(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetBootstrapped(true)
	m.SetItems(m.MainMenuItems())
	m.SetCursor(1) // Clients.
	next, _ := m.HandleSelect()
	if next.Screen() != tui.ScreenClients {
		t.Fatal("expected clients screen")
	}
}

func TestGoBackMain(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetBootstrapped(true)
	m.SetScreen(tui.ScreenVPNs)
	m.SetItems(tui.VPNMenuItemsForTest())
	next, _ := m.GoBackMain()
	if next.Screen() != tui.ScreenMain {
		t.Fatal("expected main screen")
	}
}

func TestTestModelAccessors(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetBusyPercent(50)
	m.SetBusyLabel("label")
	m.SetIgnoreEnter(true)
	m.SetFrozenCursor(3)
	if m.BusyPercent() != 50 || m.BusyLabel() != "label" || !m.IgnoreEnter() || m.FrozenCursor() != 3 {
		t.Fatal("accessor mismatch")
	}
	m.SetOrch(nil)
}
