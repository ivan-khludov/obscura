package tui_test

import (
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/tui"
)

func TestBackupSubmenuItems(t *testing.T) {
	items := tui.BackupMenuItemsForTest()
	if len(items) != 4 || items[0] != "Create backup" || items[2] != "Restore backup" {
		t.Fatalf("unexpected backup menu: %#v", items)
	}
}

func TestSystemMenuItems(t *testing.T) {
	items := tui.SystemMenuItemsForTest()
	if len(items) != 6 || items[3] != "SSH port" {
		t.Fatalf("unexpected system menu: %#v", items)
	}
}

func TestVPNMenuItemsForTest(t *testing.T) {
	items := tui.VPNMenuItemsForTest()
	if len(items) != 5 || items[0] != "Create VPN" {
		t.Fatalf("unexpected vpn menu: %#v", items)
	}
}

func TestClientMenuItemsForTest(t *testing.T) {
	items := tui.ClientMenuItemsForTest()
	if len(items) != 5 || items[0] != "Add client" {
		t.Fatalf("unexpected client menu: %#v", items)
	}
}

func TestFormatBackupListForTest(t *testing.T) {
	if tui.FormatBackupListForTest(nil) != "No backups" {
		t.Fatal("expected no backups message")
	}
	entries := []orchestration.BackupEntry{{Name: "b1.tar.gz"}}
	out := tui.FormatBackupListForTest(entries)
	if !strings.Contains(out, "b1.tar.gz") {
		t.Fatalf("unexpected format: %q", out)
	}
}

func TestLoadMenuStatusCmdForTest(t *testing.T) {
	_, svc := newTestServiceModel(t)
	orch := orchestration.New(svc)
	msg := firstTeaMsg(tui.LoadMenuStatusCmdForTest(orch))
	if msg == nil {
		t.Fatal("expected menu status msg")
	}
}

func TestHandleSelectBackupMenu(t *testing.T) {
	m, _ := newTestServiceModel(t)
	m.SetBootstrapped(true)
	m.SetScreen(tui.ScreenBackup)
	m.SetItems(tui.BackupMenuItemsForTest())
	m.SetCursor(0)
	next, cmd := m.HandleSelect()
	if !next.Busy() || cmd == nil {
		t.Fatal("expected busy create backup")
	}

	m2 := next
	m2.SetBusy(false)
	m2.SetScreen(tui.ScreenBackup)
	m2.SetItems(tui.BackupMenuItemsForTest())
	m2.SetCursor(1)
	next2, cmd2 := m2.HandleSelect()
	if !next2.Busy() || cmd2 == nil {
		t.Fatal("expected busy list backups")
	}

	m3 := tui.NewModelForTest(nil, nil)
	m3.SetBootstrapped(true)
	m3.SetScreen(tui.ScreenBackup)
	m3.SetItems(tui.BackupMenuItemsForTest())
	m3.SetCursor(3)
	next3, _ := m3.HandleSelect()
	if next3.Screen() != tui.ScreenMain {
		t.Fatal("expected back to main")
	}
}

func TestHandleSelectSystemMenu(t *testing.T) {
	m, _ := newTestServiceModel(t)
	m.SetBootstrapped(true)
	m.SetScreen(tui.ScreenSystem)
	m.SetItems(tui.SystemMenuItemsForTest())
	for _, cursor := range []int{0, 1, 4} {
		mm := m
		mm.SetCursor(cursor)
		next, cmd := mm.HandleSelect()
		if !next.Busy() || cmd == nil {
			t.Fatalf("expected busy for cursor %d", cursor)
		}
	}
	m2 := tui.NewModelForTest(nil, nil)
	m2.SetBootstrapped(true)
	m2.SetScreen(tui.ScreenSystem)
	m2.SetItems(tui.SystemMenuItemsForTest())
	m2.SetCursor(5)
	next2, _ := m2.HandleSelect()
	if next2.Screen() != tui.ScreenMain {
		t.Fatal("expected back to main")
	}
}

func TestHandleSelectUninstallAndQuit(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetBootstrapped(true)
	m.SetItems(m.MainMenuItems())
	m.SetCursor(len(m.Items()) - 2)
	next, _ := m.HandleSelect()
	if next.Message() != "Run: obscura uninstall --dry-run" {
		t.Fatalf("unexpected uninstall message: %q", next.Message())
	}
	m2 := tui.NewModelForTest(nil, nil)
	m2.SetBootstrapped(true)
	m2.SetItems(m2.MainMenuItems())
	m2.SetCursor(len(m2.Items()) - 1)
	next2, cmd := m2.HandleSelect()
	if !next2.Quitting() || cmd == nil {
		t.Fatal("expected quit")
	}
}
