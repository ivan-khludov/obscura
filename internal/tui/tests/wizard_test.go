package tui_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/config"
	"github.com/ivan-khludov/obscura/internal/domain"
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

func TestCreateVPNWizardRejectsSSHPort(t *testing.T) {
	dir := t.TempDir()
	app := &config.App{
		DataDir:      dir,
		ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode:      true,
	}
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	man.SetSSHPort(22)
	_ = man.Save()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	m := tui.NewModelForTest(app, orchestration.New(svc))
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Protocol: "trojan"})
	next, _ := m.WizardAcceptCreatePort("22")
	if !strings.Contains(next.Wizard().StepError, "reserved for SSH") {
		t.Fatalf("expected SSH reserved error, got prompt=%q stepError=%q", next.Wizard().Prompt, next.Wizard().StepError)
	}
}

// TestCreateVPNWizardHTTPClientName verifies HTTP create wizard finishes after client name.

func TestWizardConfirmEnterRemoveClient(t *testing.T) {
	m, svc := newTestServiceModel(t)
	ctx := context.Background()
	_, err := svc.CreateVPN(ctx, service.CreateVPNInput{
		Name: "main", Protocol: "socks5", Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = svc.AddClient(ctx, service.AddClientInput{VPNName: "main", Name: "phone"}, true)
	if err != nil {
		t.Fatal(err)
	}
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardRemoveClient, StepType: tui.StepConfirm,
		VPNName: "main", ClientName: "phone",
	})
	next, cmd := m.WizardConfirmEnter()
	if next.Mode() != tui.ModeMenu || cmd == nil {
		t.Fatal("expected async remove")
	}
}

func TestWizardAcceptSSHPortSamePort(t *testing.T) {
	m, _ := newTestServiceModel(t)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardSetSSHPort, StepType: tui.StepText, Prompt: "SSH port [22]:"})
	next, cmd := m.WizardAcceptSSHPort("22")
	if next.Wizard().StepType != tui.StepNotice || cmd != nil {
		t.Fatal("expected notice for same port")
	}
}

func TestWizardAcceptSSHPortChange(t *testing.T) {
	m, _ := newTestServiceModel(t)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardSetSSHPort, StepType: tui.StepText, Prompt: "SSH port [22]:"})
	next, cmd := m.WizardAcceptSSHPort("2222")
	if cmd == nil {
		t.Fatal("expected set port cmd")
	}
	msg := firstTeaMsg(cmd)
	done, _ := next.Update(msg)
	// DevMode rejects ssh port changes; wizard stays open with retry prompt.
	if done.Mode() != tui.ModeWizard {
		t.Fatalf("expected wizard mode after dev-mode rejection, got %v", done.Mode())
	}
	if !strings.Contains(done.Wizard().Prompt, "try again") {
		t.Fatalf("expected retry prompt, got %q", done.Wizard().Prompt)
	}
}

func TestWizardFinishSetCongestion(t *testing.T) {
	m, _ := newTestServiceModel(t)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{Kind: tui.WizardSetCongestion})
	next, cmd := m.WizardFinishSetCongestion("bbr")
	if next.Mode() != tui.ModeMenu || cmd == nil {
		t.Fatal("expected async congestion apply")
	}
}

func TestWizardConfirmEnterRestoreBackup(t *testing.T) {
	m, _ := newTestServiceModel(t)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		Kind: tui.WizardRestoreBackup, StepType: tui.StepConfirm, BackupPath: "/tmp/b.tar.gz",
	})
	next, cmd := m.WizardConfirmEnter()
	if next.Mode() != tui.ModeMenu || cmd == nil {
		t.Fatal("expected async restore")
	}
}
