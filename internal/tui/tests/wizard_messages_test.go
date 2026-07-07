package tui_test

import (
	"errors"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/tui"
)

func TestMessageTypesThroughUpdate(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardAddClient, Loading: true})

	vpns := []orchestration.VPNView{{Name: "main", Protocol: "socks5", Listen: domain.ListenOptions{ListenPort: 1080}}}
	next, _ := m.Update(tui.NewVPNListMsgForTest(vpns, nil))
	if next.Wizard().StepType != tui.StepPicker {
		t.Fatal("expected vpn list applied")
	}

	m2 := next
	m2.SetWizard(tui.WizardStateForTest{Kind: tui.WizardShowClient, Loading: true, VPNName: "main"})
	next2, _ := m2.Update(tui.NewClientListMsgForTest([]orchestration.ClientView{{Name: "phone"}}, nil))
	if next2.Wizard().StepType != tui.StepPicker {
		t.Fatal("expected client list applied")
	}

	m3 := tui.NewModelForTest(nil, nil)
	m3.SetMode(tui.ModeWizard)
	m3.SetWizard(tui.WizardStateForTest{Kind: tui.WizardRestoreBackup, Loading: true})
	next3, _ := m3.Update(tui.NewBackupListMsgForTest(nil, errors.New("list failed")))
	if next3.Wizard().StepType != tui.StepNotice {
		t.Fatal("expected backup error notice")
	}

	m4 := tui.NewModelForTest(nil, nil)
	m4.SetMode(tui.ModeWizard)
	m4.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Loading: true})
	next4, _ := m4.Update(tui.NewProtocolListMsgForTest(nil, errors.New("protocols failed")))
	if next4.Wizard().StepType != tui.StepNotice {
		t.Fatal("expected protocol error notice")
	}

	m5, _ := newTestServiceModel(t)
	m5.SetMode(tui.ModeWizard)
	m5.SetWizard(tui.WizardStateForTest{Kind: tui.WizardSetSSHPort, StepType: tui.StepText, Prompt: "SSH port [22]:"})
	next5, _ := m5.Update(tui.NewSSHPortSetMsgForTest(2222, errors.New("port busy")))
	if next5.Wizard().StepType != tui.StepText {
		t.Fatal("expected ssh port retry text step")
	}

	m6 := tui.NewModelForTest(nil, nil)
	m6.SetBusy(true)
	next6, cmd := m6.Update(tui.TickMsg{})
	if cmd == nil {
		t.Fatal("expected tick cmd while busy")
	}
	if next6.BusyLabel() == "" && next6.BusyPercent() < 0 {
		_ = next6.BusyLabel()
	}
	_ = firstTeaMsg(tui.TickCmdForTest())
	_ = firstTeaMsg(tui.ClearIgnoreEnterCmdForTest())
}

func TestTickMsgIgnoredWhenNotBusy(t *testing.T) {
	m := tui.NewModelForTest(nil, nil)
	next, cmd := m.Update(tui.TickMsg{})
	if cmd != nil {
		t.Fatal("expected no cmd when not busy")
	}
	_ = next
}
