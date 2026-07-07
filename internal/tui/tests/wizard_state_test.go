package tui_test

import (
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/tui"
)

func TestVPNLabelForTest(t *testing.T) {
	label := tui.VPNLabelForTest(orchestration.VPNView{
		Name: "main", Protocol: "socks5",
		Listen: domain.ListenOptions{ListenPort: 1080},
	})
	if label != "main :1080 (socks5)" {
		t.Fatalf("unexpected label: %q", label)
	}
}

func TestClientLabelForTest(t *testing.T) {
	if tui.ClientLabelForTest(orchestration.ClientView{Name: "phone"}) != "phone" {
		t.Fatal("expected client name label")
	}
}

func TestStripWizardErrorSuffixForTest(t *testing.T) {
	prompt := "Port [1080]: (already in use — try again)"
	if got := tui.StripWizardErrorSuffixForTest(prompt); got != "Port [1080]:" {
		t.Fatalf("expected stripped prompt, got %q", got)
	}
	if tui.StripWizardErrorSuffixForTest("VPN name:") != "VPN name:" {
		t.Fatal("expected unchanged prompt")
	}
}

func TestSnapshotForHistoryForTest(t *testing.T) {
	w := tui.WizardStateForTest{
		Kind: tui.WizardCreateVPN, Prompt: "Port [1080]:",
		StepError:     "boom",
		WizardHistory: []tui.WizardStateForTest{{Kind: tui.WizardCreateVPN}},
	}
	snap := tui.SnapshotForHistoryForTest(w)
	if snap.StepError != "" {
		t.Fatal("snapshot should clear step error")
	}
	if len(snap.WizardHistory) != 0 {
		t.Fatal("snapshot should clear history")
	}
}

func TestEditVPNFieldsForTest(t *testing.T) {
	httpFields := tui.EditVPNFieldsForTest(orchestration.VPNView{Protocol: "http"})
	if len(httpFields) != 5 || httpFields[4] != "TLS" {
		t.Fatalf("expected TLS field for http, got %#v", httpFields)
	}
	socksFields := tui.EditVPNFieldsForTest(orchestration.VPNView{Protocol: "socks5"})
	if len(socksFields) != 4 {
		t.Fatalf("expected 4 fields for socks5, got %#v", socksFields)
	}
}
