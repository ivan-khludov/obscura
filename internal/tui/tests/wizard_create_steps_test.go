package tui_test

import (
	"github.com/ivan-khludov/obscura/internal/tui"
	"testing"
)

func TestSetPickerStepForTest(t *testing.T) {
	w := tui.WizardStateForTest{Kind: tui.WizardCreateVPN, StepType: tui.StepPicker}
	tui.SetPickerStepForTest(&w, "Select protocol:", "pick one", []string{"socks5", "http"}, []string{"hint1", "hint2"})
	if w.Prompt != "Select protocol:" {
		t.Fatalf("unexpected wizard state: %#v", w)
	}
	if len(w.Picker) != 2 || w.PickerHints[0] != "hint1" {
		t.Fatalf("unexpected picker: %#v", w.Picker)
	}
}

func TestInferCreateStepViaWizardState(t *testing.T) {
	cases := []struct {
		prompt string
		step   int
	}{
		{"VPN name:", tui.StepText},
		{"Select protocol:", tui.StepPicker},
		{"Port [1080]:", tui.StepText},
		{"Transport options:", tui.StepPicker},
		{"Client name:", tui.StepText},
	}
	for _, tc := range cases {
		w := tui.WizardStateForTest{Kind: tui.WizardCreateVPN, Prompt: tc.prompt, StepType: tc.step}
		m := tui.NewModelForTest(nil, nil)
		m.SetMode(tui.ModeWizard)
		m.SetWizard(w)
		view := m.RenderPanel()
		if view == "" {
			t.Fatalf("expected panel for %q", tc.prompt)
		}
	}
}
