package shadowsocks_test

import (
	"io"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol/shadowsocks"
)

type stuckPortReader struct {
	hi, lo byte
}

func newStuckPortReader(publicPort int) stuckPortReader {
	mod := publicPort - 20000
	return stuckPortReader{byte(mod >> 8), byte(mod)}
}

func (r stuckPortReader) Read(p []byte) (int, error) {
	if len(p) < 2 {
		return 0, io.ErrShortBuffer
	}
	p[0], p[1] = r.hi, r.lo
	return 2, nil
}

func TestValidateOptions(t *testing.T) {
	tests := []struct {
		name    string
		data    shadowsocks.ProtocolData
		wantErr bool
		errSub  string
	}{
		{
			name: "valid multiplex",
			data: shadowsocks.ProtocolData{
				Method: "2022-blake3-aes-128-gcm", ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
				Multiplex: true,
			},
		},
		{
			name: "valid plugin",
			data: shadowsocks.ProtocolData{
				Method: "2022-blake3-aes-128-gcm", ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
				Plugin: "obfs-local", PluginOpts: shadowsocks.DefaultObfsPluginOpts,
			},
		},
		{
			name: "valid shadowtls",
			data: shadowsocks.ProtocolData{
				Method: "2022-blake3-aes-128-gcm", ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
				ShadowTLS: true, ShadowTLSPassword: "secret", ShadowTLSHandshake: "www.bing.com",
			},
		},
		{
			name: "plugin without opts",
			data: shadowsocks.ProtocolData{
				Method: "2022-blake3-aes-128-gcm", ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
				Plugin: "obfs-local",
			},
			wantErr: true,
		},
		{
			name: "unsupported plugin",
			data: shadowsocks.ProtocolData{
				Method: "2022-blake3-aes-128-gcm", ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
				Plugin: "bad-plugin", PluginOpts: "x",
			},
			wantErr: true,
			errSub:  "unsupported shadowsocks plugin",
		},
		{
			name: "shadowtls and plugin",
			data: shadowsocks.ProtocolData{
				Method: "2022-blake3-aes-128-gcm", ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
				ShadowTLS: true, ShadowTLSPassword: "secret", ShadowTLSHandshake: "www.bing.com",
				Plugin: "obfs-local", PluginOpts: "obfs=http",
			},
			wantErr: true,
		},
		{
			name: "shadowtls password missing",
			data: shadowsocks.ProtocolData{
				Method: "2022-blake3-aes-128-gcm", ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
				ShadowTLS: true, ShadowTLSHandshake: "www.bing.com",
			},
			wantErr: true,
			errSub:  "shadowtls_password is required",
		},
		{
			name: "shadowtls handshake missing",
			data: shadowsocks.ProtocolData{
				Method: "2022-blake3-aes-128-gcm", ServerPassword: "8JCsPssfgS8tiRwiMlhARg==",
				ShadowTLS: true, ShadowTLSPassword: "secret",
			},
			wantErr: true,
			errSub:  "shadowtls_handshake is required",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := shadowsocks.ValidateOptions(tc.data)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateOptions() err=%v wantErr=%v", err, tc.wantErr)
			}
			if tc.errSub != "" && (err == nil || !strings.Contains(err.Error(), tc.errSub)) {
				t.Fatalf("ValidateOptions() err=%v want substring %q", err, tc.errSub)
			}
		})
	}
}

func TestSupportsMultiUser(t *testing.T) {
	if !shadowsocks.SupportsMultiUser("2022-blake3-aes-128-gcm") {
		t.Fatal("expected aes-128 multi-user")
	}
	if !shadowsocks.SupportsMultiUser("2022-blake3-aes-256-gcm") {
		t.Fatal("expected aes-256 multi-user")
	}
	if shadowsocks.SupportsMultiUser("2022-blake3-chacha20-poly1305") {
		t.Fatal("chacha20 must not support multi-user")
	}
	if shadowsocks.SupportsMultiUser("unknown") {
		t.Fatal("unknown method must not support multi-user")
	}
	if shadowsocks.IsSupportedMethod("2022-blake3-chacha20-poly1305") {
		t.Fatal("chacha20 must not be a supported create method")
	}
}

func TestGenerateShadowTLSPassword(t *testing.T) {
	pw, err := shadowsocks.GenerateShadowTLSPassword()
	if err != nil {
		t.Fatal(err)
	}
	if pw == "" {
		t.Fatal("expected non-empty password")
	}
}

func TestOptionsGen_nilReceiver(t *testing.T) {
	var gen *shadowsocks.OptionsGen
	pw, err := gen.GenerateShadowTLSPassword()
	if err != nil || pw == "" {
		t.Fatalf("GenerateShadowTLSPassword() = %q, %v", pw, err)
	}
	port, err := gen.GenerateBackendPort(443)
	if err != nil || port == 0 {
		t.Fatalf("GenerateBackendPort() = %d, %v", port, err)
	}
}

func TestOptionsGen_randErrors(t *testing.T) {
	gen := &shadowsocks.OptionsGen{RandRead: failReader{}}
	if _, err := gen.GenerateShadowTLSPassword(); err == nil {
		t.Fatal("expected shadowtls password error")
	}
	if _, err := gen.GenerateBackendPort(443); err == nil {
		t.Fatal("expected backend port error")
	}
}

func TestGenerateBackendPort_packageFunc(t *testing.T) {
	port, err := shadowsocks.GenerateBackendPort(443)
	if err != nil || port == 0 || port == 443 {
		t.Fatalf("GenerateBackendPort() = %d, %v", port, err)
	}
}

func TestShadowTLSBackendPortForTest(t *testing.T) {
	data := shadowsocks.ProtocolData{ShadowTLSBackendPort: 38443}
	if got := shadowsocks.ShadowTLSBackendPortForTest(data, 443); got != 38443 {
		t.Fatalf("explicit backend port = %d", got)
	}
	if got := shadowsocks.ShadowTLSBackendPortForTest(shadowsocks.ProtocolData{}, 56000); got != 36000 {
		t.Fatalf("overflow fallback = %d", got)
	}
}

func TestGenerateBackendPort_loopExhausted(t *testing.T) {
	publicPort := 38443
	gen := &shadowsocks.OptionsGen{RandRead: newStuckPortReader(publicPort)}
	port, err := gen.GenerateBackendPort(publicPort)
	if err != nil {
		t.Fatal(err)
	}
	if port != publicPort+10000 {
		t.Fatalf("expected fallback port %d, got %d", publicPort+10000, port)
	}
}

func TestGenerateBackendPort_overflowFallback(t *testing.T) {
	// FailReader causes loop to fail immediately; fallback uses publicPort+10000 overflow path.
	// Use a reader that always returns stuck port != publicPort but we need loop exhaustion first.
	publicPort := 56000
	stuck := newStuckPortReader(38443)
	gen := &shadowsocks.OptionsGen{RandRead: stuck}
	port, err := gen.GenerateBackendPort(publicPort)
	if err != nil {
		t.Fatal(err)
	}
	if port == publicPort {
		t.Fatalf("port must differ from public port %d", publicPort)
	}
	// First successful random pick should be 38443 since stuck reader always returns that.
	if port != 38443 {
		t.Fatalf("expected first valid random port 38443, got %d", port)
	}
}

func TestGenerateBackendPort_collisionIncrement(t *testing.T) {
	publicPort := 20000
	gen := &shadowsocks.OptionsGen{RandRead: newStuckPortReader(publicPort)}
	port, err := gen.GenerateBackendPort(publicPort)
	if err != nil {
		t.Fatal(err)
	}
	if port != 30000 {
		t.Fatalf("expected fallback port 30000, got %d", port)
	}
}
