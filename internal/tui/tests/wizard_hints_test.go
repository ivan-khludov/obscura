package tui_test

import (
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/tui"
)

func TestPickerHintsMatchItems(t *testing.T) {
	checks := []struct {
		name  string
		items []string
		hints []string
	}{
		{"ssTransport", orchestration.ShadowsocksTransportModes(), tui.ShadowsocksTransportPickerHintsForTest()},
		{"trojanTransport", orchestration.InboundTransportModes("trojan"), tui.InboundTransportPickerHintsForTest("trojan")},
		{"vmessTransport", orchestration.InboundTransportModes("vmess"), tui.InboundTransportPickerHintsForTest("vmess")},
		{"vlessTransport", orchestration.InboundTransportModes("vless"), tui.InboundTransportPickerHintsForTest("vless")},
		{"vlessFlow", orchestration.VLESSFlowModes(), tui.VlessFlowPickerHintsForTest()},
		{"ssCipher", orchestration.ShadowsocksMethods(), tui.SSCipherPickerHintsForTest()},
		{"wgInterface", []string{"Direct (userspace)", "System interface"}, tui.WGInterfacePickerHintsForTest()},
		{"tuicCC", []string{"Cubic", "New Reno", "BBR"}, tui.TuicCongestionPickerHintsForTest()},
		{"tuicZeroRTT", []string{"Disabled (recommended)", "Enabled (replay risk)"}, tui.TuicZeroRTTPickerHintsForTest()},
		{"hy2Bandwidth", []string{"No limit", "Set bandwidth", "Ignore client bandwidth (BBR)"}, tui.Hy2BandwidthPickerHintsForTest()},
		{"hy2Obfs", []string{"None", "Salamander"}, tui.Hy2ObfsPickerHintsForTest()},
		{"hy2Masquerade", []string{"None", "Reverse proxy URL", "File directory"}, tui.Hy2MasqueradePickerHintsForTest()},
		{"httpTLS", []string{"No TLS", "Enable TLS"}, tui.HTTPTLSPickerHintsForTest()},
		{"vmessTLS", []string{"No TLS", "Enable TLS"}, tui.VMessTLSPickerHintsForTest()},
		{"vlessTLS", []string{"Standard TLS", "Reality"}, tui.VlessTLSModePickerHintsForTest()},
		{"realityUTLSFP", tui.RealityUTLSFingerprintModesForTest(), tui.RealityUTLSFingerprintPickerHintsForTest()},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.items) != len(tc.hints) {
				t.Fatalf("len(items)=%d len(hints)=%d", len(tc.items), len(tc.hints))
			}
		})
	}
}

func TestWizardStateActiveHint(t *testing.T) {
	w := tui.WizardStateForTest{}
	tui.SetPickerStepForTest(&w, "Transport options:", "How proxy traffic is wrapped before it reaches the server.", []string{"Direct", "Multiplex"}, []string{"a", "b"})
	w.PickerIdx = 1
	w.StepType = tui.StepPicker
	if got := tui.ActiveHintForTest(w); got != "b" {
		t.Fatalf("activeHint() = %q, want b", got)
	}
	w.PickerIdx = 0
	if got := tui.ActiveHintForTest(w); got != "a" {
		t.Fatalf("activeHint() = %q, want a", got)
	}
}

func TestRenderWizardPanelShowsHint(t *testing.T) {
	m := tui.NewModelForTest(nil)
	m.SetMode(tui.ModeWizard)
	m.SetWizard(tui.WizardStateForTest{
		StepType:   tui.StepText,
		Prompt:     "VPN name:",
		PromptHint: "Internal label for this VPN in obscura.",
		Input:      tui.NewTextInputForTest(""),
	})
	out := m.RenderPanel()
	if !strings.Contains(out, "Internal label for this VPN in obscura.") {
		t.Fatalf("expected hint in panel output, got:\n%s", out)
	}
}
