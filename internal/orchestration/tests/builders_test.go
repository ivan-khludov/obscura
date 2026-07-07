package orchestration_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/orchestration"
)

func TestDefaultListenPort(t *testing.T) {
	tests := []struct {
		protocol string
		want     int
	}{
		{"http", 8080},
		{"trojan", 443},
		{"vmess", 443},
		{"vless", 443},
		{"hysteria2", 443},
		{"tuic", 443},
		{"shadowsocks", 8388},
		{"wireguard", 51820},
		{"socks5", 1080},
		{"unknown", 1080},
	}
	for _, tt := range tests {
		if got := orchestration.DefaultListenPort(tt.protocol); got != tt.want {
			t.Fatalf("DefaultListenPort(%q) = %d, want %d", tt.protocol, got, tt.want)
		}
	}
}

func TestBuildCreateVPNInput_Defaults(t *testing.T) {
	in := orchestration.BuildCreateVPNInput(orchestration.CreateVPNRequest{
		Name: "main",
	})
	if in.Protocol != "socks5" {
		t.Fatalf("protocol = %q, want socks5", in.Protocol)
	}
	if in.Listen.Listen != "0.0.0.0" {
		t.Fatalf("listen = %q, want 0.0.0.0", in.Listen.Listen)
	}
	if in.Listen.ListenPort != 1080 {
		t.Fatalf("listen port = %d, want 1080", in.Listen.ListenPort)
	}
}

func TestBuildCreateVPNInput_HTTPTLS(t *testing.T) {
	in := orchestration.BuildCreateVPNInput(orchestration.CreateVPNRequest{
		Name:     "web",
		Protocol: "http",
		HTTPTLS:  true,
		Listen:   domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8080},
	})
	if !in.HTTP.TLS {
		t.Fatal("expected HTTP.TLS=true")
	}
}

func TestBuildCreateVPNInput_ProtocolBranches(t *testing.T) {
	t.Run("vmess", func(t *testing.T) {
		in := orchestration.BuildCreateVPNInput(orchestration.CreateVPNRequest{
			Name:     "vm",
			Protocol: "vmess",
			VMess:    orchestration.VMessCreateOptions{ServerName: "example.com"},
			Listen:   domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		})
		if in.VMess.ServerName != "example.com" {
			t.Fatalf("vmess server name = %q", in.VMess.ServerName)
		}
	})
	t.Run("vless", func(t *testing.T) {
		in := orchestration.BuildCreateVPNInput(orchestration.CreateVPNRequest{
			Name:     "vl",
			Protocol: "vless",
			VLESS:    orchestration.VLESSCreateOptions{DefaultFlow: "xtls-rprx-vision"},
			Listen:   domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		})
		if in.VLESS.DefaultFlow == "" {
			t.Fatal("expected vless options")
		}
	})
	t.Run("tuic", func(t *testing.T) {
		in := orchestration.BuildCreateVPNInput(orchestration.CreateVPNRequest{
			Name:     "tuic",
			Protocol: "tuic",
			TUIC:     orchestration.TUICCreateOptions{ServerName: "example.com"},
			Listen:   domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		})
		if in.TUIC.ServerName != "example.com" {
			t.Fatalf("tuic server name = %q", in.TUIC.ServerName)
		}
	})
	t.Run("shadowsocks listen port fallback", func(t *testing.T) {
		in := orchestration.BuildCreateVPNInput(orchestration.CreateVPNRequest{
			Name:        "ss",
			Protocol:    "shadowsocks",
			SSMethod:    "2022-blake3-aes-128-gcm",
			Shadowsocks: orchestration.ShadowsocksCreateOptions{Method: "2022-blake3-aes-128-gcm"},
			Listen:      domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 9000},
		})
		if in.Shadowsocks.ListenPort != 9000 {
			t.Fatalf("shadowsocks listen port = %d, want 9000", in.Shadowsocks.ListenPort)
		}
	})
}

func TestBuildCreateVPNInput_SharedFieldsStayProtocolScoped(t *testing.T) {
	t.Run("trojan does not inherit shadowsocks fields", func(t *testing.T) {
		in := orchestration.BuildCreateVPNInput(orchestration.CreateVPNRequest{
			Name:        "tr",
			Protocol:    "trojan",
			Enabled:     true,
			Listen:      domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
			SSMultiplex: true,
			Trojan:      orchestration.TrojanCreateOptions{Multiplex: true, ServerName: "example.com"},
		})
		if in.SSMultiplex {
			t.Fatalf("expected shadowsocks multiplex to be ignored for trojan")
		}
		if !in.Trojan.Multiplex {
			t.Fatalf("expected trojan multiplex to remain enabled")
		}
	})

	t.Run("shadowsocks keeps shadowsocks fields", func(t *testing.T) {
		in := orchestration.BuildCreateVPNInput(orchestration.CreateVPNRequest{
			Name:               "ss",
			Protocol:           "shadowsocks",
			Enabled:            true,
			Listen:             domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8388},
			SSMethod:           "2022-blake3-aes-128-gcm",
			SSMultiplex:        true,
			SSMultiplexPadding: true,
			Shadowsocks: orchestration.ShadowsocksCreateOptions{
				Method:     "2022-blake3-aes-128-gcm",
				Multiplex:  true,
				ListenPort: 8388,
			},
		})
		if !in.SSMultiplex || !in.SSMultiplexPadding {
			t.Fatalf("expected shadowsocks multiplex flags to be set")
		}
		if in.Shadowsocks.ListenPort != 8388 {
			t.Fatalf("expected shadowsocks listen port 8388, got %d", in.Shadowsocks.ListenPort)
		}
	})
}

func TestBuildUpdateVPNInput(t *testing.T) {
	t.Run("client host conflict", func(t *testing.T) {
		host := "example.com"
		_, err := orchestration.BuildUpdateVPNInput(orchestration.UpdateVPNRequest{
			ClientHost:      &host,
			ClearClientHost: true,
		})
		if err == nil {
			t.Fatal("expected mutually exclusive client-host error")
		}
	})
	t.Run("full fields", func(t *testing.T) {
		name := "new"
		enabled := true
		tls := true
		host := "vpn.example.com"
		in, err := orchestration.BuildUpdateVPNInput(orchestration.UpdateVPNRequest{
			Name:       &name,
			Enabled:    &enabled,
			HTTPTLS:    &tls,
			ClientHost: &host,
		})
		if err != nil {
			t.Fatal(err)
		}
		if in.Name == nil || *in.Name != "new" {
			t.Fatal("expected name")
		}
		if in.Enabled == nil || !*in.Enabled {
			t.Fatal("expected enabled")
		}
		if in.HTTPTLS == nil || !*in.HTTPTLS {
			t.Fatal("expected httptls")
		}
		if in.ClientHost == nil || *in.ClientHost != host {
			t.Fatal("expected client host")
		}
	})
	t.Run("clear client host", func(t *testing.T) {
		in, err := orchestration.BuildUpdateVPNInput(orchestration.UpdateVPNRequest{
			ClearClientHost: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if in.ClientHost == nil || *in.ClientHost != "" {
			t.Fatal("expected cleared client host")
		}
	})
	t.Run("blank name ignored", func(t *testing.T) {
		blank := "   "
		in, err := orchestration.BuildUpdateVPNInput(orchestration.UpdateVPNRequest{Name: &blank})
		if err != nil {
			t.Fatal(err)
		}
		if in.Name != nil {
			t.Fatal("expected blank name to be ignored")
		}
	})
}

func TestBuildUpdateClientInput(t *testing.T) {
	t.Run("ignores blank rename", func(t *testing.T) {
		blank := ""
		in := orchestration.BuildUpdateClientInput(orchestration.UpdateClientRequest{
			VPNName: "main",
			Name:    "phone",
			NewName: &blank,
		})
		if in.NewName != nil {
			t.Fatalf("expected blank rename to be ignored")
		}
	})
	t.Run("full fields", func(t *testing.T) {
		newName := "tablet"
		user := "alice"
		pass := "secret"
		enabled := false
		in := orchestration.BuildUpdateClientInput(orchestration.UpdateClientRequest{
			VPNName:  "main",
			Name:     "phone",
			NewName:  &newName,
			Username: &user,
			Password: &pass,
			Enabled:  &enabled,
		})
		if in.NewName == nil || *in.NewName != "tablet" {
			t.Fatal("expected new name")
		}
		if in.Username == nil || *in.Username != user {
			t.Fatal("expected username")
		}
		if in.Password == nil || *in.Password != pass {
			t.Fatal("expected password")
		}
		if in.Enabled == nil || *in.Enabled {
			t.Fatal("expected disabled")
		}
	})
}

func TestCreateRequestParity_CLIAndTUIShapeProduceSameInput(t *testing.T) {
	cliReq := orchestration.CreateVPNRequest{
		Name:              "vmess-main",
		Protocol:          "vmess",
		ClientHost:        "vpn.example.com",
		Listen:            domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
		Enabled:           true,
		InitialClientName: "phone",
		Trojan: orchestration.TrojanCreateOptions{
			ServerName:       "vpn.example.com",
			Multiplex:        true,
			MultiplexPadding: true,
		},
		VMess: orchestration.VMessCreateOptions{
			ServerName:       "vpn.example.com",
			Multiplex:        true,
			MultiplexPadding: true,
		},
		MultiplexRequested:        true,
		MultiplexPaddingRequested: true,
	}
	tuiReq := cliReq

	if err := orchestration.ValidateCreateVPNRequest(cliReq); err != nil {
		t.Fatalf("cli request should be valid: %v", err)
	}
	if err := orchestration.ValidateCreateVPNRequest(tuiReq); err != nil {
		t.Fatalf("tui request should be valid: %v", err)
	}

	cliInput := orchestration.BuildCreateVPNInput(cliReq)
	tuiInput := orchestration.BuildCreateVPNInput(tuiReq)
	if diff := cmp.Diff(cliInput, tuiInput); diff != "" {
		t.Fatalf("expected same create input for cli and tui (-want +got):\n%s", diff)
	}
}

func TestCreateRequestParity_ProtocolOptionsMatrix(t *testing.T) {
	tests := []struct {
		name   string
		cliReq orchestration.CreateVPNRequest
		tuiReq orchestration.CreateVPNRequest
	}{
		{
			name: "shadowsocks transport options parity",
			cliReq: orchestration.CreateVPNRequest{
				Name:     "ss",
				Protocol: "shadowsocks",
				Enabled:  true,
				Listen:   domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8388},
				SSMethod: "2022-blake3-aes-128-gcm",
				SSPlugin: "obfs-local",
				Shadowsocks: orchestration.BuildShadowsocksCreateOptions(
					"2022-blake3-aes-128-gcm", "obfs-local", "obfs=tls",
					true, true, true, "www.bing.com", 443, true, 8388,
				),
			},
			tuiReq: orchestration.CreateVPNRequest{
				Name:     "ss",
				Protocol: "shadowsocks",
				Enabled:  true,
				Listen:   domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8388},
				SSMethod: "2022-blake3-aes-128-gcm",
				SSPlugin: "obfs-local",
				Shadowsocks: orchestration.BuildShadowsocksCreateOptions(
					"2022-blake3-aes-128-gcm", "obfs-local", "obfs=tls",
					true, true, true, "www.bing.com", 443, true, 8388,
				),
			},
		},
		{
			name: "hysteria2 options parity",
			cliReq: orchestration.CreateVPNRequest{
				Name:      "hy2",
				Protocol:  "hysteria2",
				Enabled:   true,
				Listen:    domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
				Hysteria2: orchestration.BuildHysteria2CreateOptions("example.com", 100, 200, false, "auto", "file:///var/www"),
			},
			tuiReq: orchestration.CreateVPNRequest{
				Name:      "hy2",
				Protocol:  "hysteria2",
				Enabled:   true,
				Listen:    domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
				Hysteria2: orchestration.BuildHysteria2CreateOptions("example.com", 100, 200, false, "auto", "file:///var/www"),
			},
		},
		{
			name: "wireguard options parity",
			cliReq: orchestration.CreateVPNRequest{
				Name:      "wg",
				Protocol:  "wireguard",
				Enabled:   true,
				Listen:    domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 51820},
				Wireguard: orchestration.BuildWireguardCreateOptions(true, "", 1408),
			},
			tuiReq: orchestration.CreateVPNRequest{
				Name:      "wg",
				Protocol:  "wireguard",
				Enabled:   true,
				Listen:    domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 51820},
				Wireguard: orchestration.BuildWireguardCreateOptions(true, "", 1408),
			},
		},
		{
			name: "tuic options parity",
			cliReq: orchestration.CreateVPNRequest{
				Name:     "tuic",
				Protocol: "tuic",
				Enabled:  true,
				Listen:   domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
				TUIC:     orchestration.BuildTUICCreateOptions("example.com", "bbr", true),
			},
			tuiReq: orchestration.CreateVPNRequest{
				Name:     "tuic",
				Protocol: "tuic",
				Enabled:  true,
				Listen:   domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 443},
				TUIC:     orchestration.BuildTUICCreateOptions("example.com", "bbr", true),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cliInput := orchestration.BuildCreateVPNInput(tt.cliReq)
			tuiInput := orchestration.BuildCreateVPNInput(tt.tuiReq)
			if diff := cmp.Diff(cliInput, tuiInput); diff != "" {
				t.Fatalf("protocol options parity mismatch (-cli +tui):\n%s", diff)
			}
		})
	}
}
