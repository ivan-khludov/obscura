package tui_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/tui"
)

func TestApplyVPNListEmpty(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardAddClient, Loading: true})
	next, _ := m.Update(tui.NewVPNListMsgForTest(nil, nil))
	if next.Wizard().Notice != "No VPNs — create one first" {
		t.Fatalf("unexpected notice: %q", next.Wizard().Notice)
	}
}

func TestApplyVPNListError(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardAddClient, Loading: true})
	next, _ := m.Update(tui.NewVPNListMsgForTest(nil, errors.New("db error")))
	if next.Wizard().Notice != "db error" {
		t.Fatalf("unexpected notice: %q", next.Wizard().Notice)
	}
}

func TestApplyClientListEmpty(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardShowClient, Loading: true, VPNName: "main"})
	next, _ := m.Update(tui.NewClientListMsgForTest(nil, nil))
	if next.Wizard().Notice != "No clients on this VPN" {
		t.Fatalf("unexpected notice: %q", next.Wizard().Notice)
	}
}

func TestApplyBackupListSuccess(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardRestoreBackup, Loading: true})
	entries := []orchestration.BackupEntry{{Name: "backup1.tar.gz", Path: "/tmp/b1"}}
	next, _ := m.Update(tui.NewBackupListMsgForTest(entries, nil))
	if next.Wizard().StepType != tui.StepPicker || next.Wizard().Prompt != "Select backup:" {
		t.Fatalf("unexpected wizard: %#v", next.Wizard())
	}
}

func TestApplyCongestionListEmpty(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardSetCongestion, Loading: true})
	next, _ := m.Update(tui.NewCongestionListMsgForTest(nil, "", nil))
	if next.Wizard().Notice != "No congestion control algorithms available" {
		t.Fatalf("unexpected notice: %q", next.Wizard().Notice)
	}
}

func TestApplySSHPortSetSuccess(t *testing.T) {
	m, _ := newTestServiceModel(t)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardSetSSHPort, StepType: tui.StepText})
	next, cmd := m.Update(tui.NewSSHPortSetMsgForTest(2222, nil))
	if next.Mode() != tui.ModeMenu {
		t.Fatalf("expected menu mode, got %v", next.Mode())
	}
	if cmd == nil {
		t.Fatal("expected async cmd")
	}
}

func TestApplyCreateVPNResultSuccess(t *testing.T) {
	m, _ := newTestServiceModel(t)
	m.SetMode(tui.ModeWizard)
	m.SetBusy(true)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Protocol: "socks5"})
	next, cmd := m.Update(tui.NewCreateVPNResultMsgForTest("Created VPN", nil))
	if next.Mode() != tui.ModeMenu {
		t.Fatal("expected menu mode after create")
	}
	if next.Message() != "Created VPN" {
		t.Fatalf("unexpected message: %q", next.Message())
	}
	if cmd == nil {
		t.Fatal("expected refresh cmd")
	}
}

func TestActionDoneRefreshMenu(t *testing.T) {
	m, _ := newTestServiceModel(t)
	m.SetBusy(true)
	next, cmd := m.Update(tui.NewActionDoneMsgForTest("done", nil, true))
	if next.Message() != "done" {
		t.Fatal("expected message")
	}
	if cmd == nil {
		t.Fatal("expected batch cmd")
	}
}

func TestVPNListIgnoredInMenuMode(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	next, cmd := m.Update(tui.NewVPNListMsgForTest([]orchestration.VPNView{{Name: "x"}}, nil))
	if cmd != nil || next.Mode() != tui.ModeMenu {
		t.Fatal("menu mode should ignore vpn list")
	}
}

func TestApplyProtocolListEmpty(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Loading: true})
	next, _ := m.Update(tui.NewProtocolListMsgForTest(nil, nil))
	if next.Wizard().Notice != "No protocols available" {
		t.Fatalf("unexpected notice: %q", next.Wizard().Notice)
	}
}

func TestApplyClientListError(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardShowClient, Loading: true})
	next, _ := m.Update(tui.NewClientListMsgForTest(nil, errors.New("load failed")))
	if next.Wizard().Notice != "load failed" {
		t.Fatalf("unexpected notice: %q", next.Wizard().Notice)
	}
}

func TestApplyCongestionListMarksCurrent(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardSetCongestion, Loading: true})
	next, _ := m.Update(tui.NewCongestionListMsgForTest([]string{"bbr", "cubic"}, "cubic", nil))
	if !strings.Contains(next.Wizard().Picker[1], "(current)") {
		t.Fatalf("expected current marker, got %#v", next.Wizard().Picker)
	}
}
