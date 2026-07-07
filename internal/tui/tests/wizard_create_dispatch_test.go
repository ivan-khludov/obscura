package tui_test

import (
	"testing"

	"github.com/ivan-khludov/obscura/internal/tui"
)

func TestWizardCreateVPNPickerDispatch_Table(t *testing.T) {
	tests := []struct {
		name       string
		prepare    func(*tui.TestModel) *tui.TestModel
		idx        int
		wantPrompt string
	}{
		{
			name: "protocol socks5 -> port prompt",
			prepare: func(m *tui.TestModel) *tui.TestModel {
				m.SetWizard(tui.WizardStateForTest{
					Kind:            tui.WizardCreateVPN,
					Prompt:          "Select protocol:",
					ProtocolOptions: []string{"socks5", "http"},
				})
				return m
			},
			idx:        0,
			wantPrompt: "Port [1080]:",
		},
		{
			name: "protocol shadowsocks -> cipher prompt",
			prepare: func(m *tui.TestModel) *tui.TestModel {
				m.SetWizard(tui.WizardStateForTest{
					Kind:            tui.WizardCreateVPN,
					Prompt:          "Select protocol:",
					ProtocolOptions: []string{"shadowsocks"},
				})
				return m
			},
			idx:        0,
			wantPrompt: "Select cipher:",
		},
		{
			name: "http tls picker -> client host prompt",
			prepare: func(m *tui.TestModel) *tui.TestModel {
				m.SetWizard(tui.WizardStateForTest{
					Kind:     tui.WizardCreateVPN,
					Protocol: "http",
					Prompt:   "Enable TLS?",
				})
				return m
			},
			idx:        1,
			wantPrompt: "Client host [auto]:",
		},
		{
			name: "hy2 bandwidth picker -> obfuscation prompt",
			prepare: func(m *tui.TestModel) *tui.TestModel {
				m.SetWizard(tui.WizardStateForTest{
					Kind:     tui.WizardCreateVPN,
					Protocol: "hysteria2",
					Prompt:   "Bandwidth:",
				})
				return m
			},
			idx:        0,
			wantPrompt: "Obfuscation:",
		},
		{
			name: "vless flow picker -> transport prompt",
			prepare: func(m *tui.TestModel) *tui.TestModel {
				m.SetWizard(tui.WizardStateForTest{
					Kind:     tui.WizardCreateVPN,
					Protocol: "vless",
					Prompt:   "VLESS flow:",
					Picker:   []string{"None", "XTLS Vision"},
				})
				return m
			},
			idx:        0,
			wantPrompt: "Transport options:",
		},
		{
			name: "wireguard interface -> mtu prompt",
			prepare: func(m *tui.TestModel) *tui.TestModel {
				m.SetWizard(tui.WizardStateForTest{
					Kind:     tui.WizardCreateVPN,
					Protocol: "wireguard",
					Prompt:   "WireGuard interface mode:",
					Picker:   []string{"Direct (userspace)", "System interface"},
				})
				return m
			},
			idx:        1,
			wantPrompt: "MTU [1408, empty=default]:",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := tc.prepare(tui.NewModelForTest(nil, nil))
			next, _, ok := m.WizardCreateVPNPickerEnter(tc.idx)
			if !ok {
				t.Fatal("expected picker case handled")
			}
			if next.Wizard().Prompt != tc.wantPrompt {
				t.Fatalf("prompt = %q, want %q", next.Wizard().Prompt, tc.wantPrompt)
			}
		})
	}
}

func TestWizardCreateVPNTextDispatch_Table(t *testing.T) {
	tests := []struct {
		name       string
		prepare    func(*tui.TestModel) *tui.TestModel
		input      string
		wantPrompt string
	}{
		{
			name: "client host -> client name",
			prepare: func(m *tui.TestModel) *tui.TestModel {
				m.SetWizard(tui.WizardStateForTest{
					Kind:   tui.WizardCreateVPN,
					Prompt: "Client host [auto]:",
				})
				return m
			},
			input:      "",
			wantPrompt: "Client name:",
		},
		{
			name: "tuic sni -> congestion",
			prepare: func(m *tui.TestModel) *tui.TestModel {
				m.SetWizard(tui.WizardStateForTest{
					Kind:     tui.WizardCreateVPN,
					Protocol: "tuic",
					Prompt:   "TLS server name (SNI) [auto]:",
				})
				return m
			},
			input:      "example.com",
			wantPrompt: "Congestion control:",
		},
		{
			name: "trojan fallback -> client host",
			prepare: func(m *tui.TestModel) *tui.TestModel {
				m.SetWizard(tui.WizardStateForTest{
					Kind:                tui.WizardCreateVPN,
					Protocol:            "trojan",
					Prompt:              "Fallback port [0=disabled]:",
					TrojanPendingPrompt: "fallback",
				})
				return m
			},
			input:      "0",
			wantPrompt: "Client host [auto]:",
		},
		{
			name: "socks5 port -> client host",
			prepare: func(m *tui.TestModel) *tui.TestModel {
				m.SetWizard(tui.WizardStateForTest{
					Kind:     tui.WizardCreateVPN,
					Protocol: "socks5",
					Prompt:   "Port [1080]:",
				})
				return m
			},
			input:      "1080",
			wantPrompt: "Client host [auto]:",
		},
		{
			name: "shadowtls handshake -> client host",
			prepare: func(m *tui.TestModel) *tui.TestModel {
				m.SetWizard(tui.WizardStateForTest{
					Kind:     tui.WizardCreateVPN,
					Protocol: "shadowsocks",
					Prompt:   "ShadowTLS handshake server [www.bing.com]:",
				})
				return m
			},
			input:      "example.com",
			wantPrompt: "Client host [auto]:",
		},
		{
			name: "wireguard subnet -> interface picker",
			prepare: func(m *tui.TestModel) *tui.TestModel {
				m.SetWizard(tui.WizardStateForTest{
					Kind:     tui.WizardCreateVPN,
					Protocol: "wireguard",
					Prompt:   "Subnet [10.8.0.1/24]:",
				})
				return m
			},
			input:      "10.8.0.1/24",
			wantPrompt: "WireGuard interface mode:",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := tc.prepare(tui.NewModelForTest(nil, nil))
			next, _, ok := m.WizardCreateVPNTextEnter(tc.input)
			if !ok {
				t.Fatal("expected text case handled")
			}
			if next.Wizard().Prompt != tc.wantPrompt {
				t.Fatalf("prompt = %q, want %q", next.Wizard().Prompt, tc.wantPrompt)
			}
		})
	}
}
