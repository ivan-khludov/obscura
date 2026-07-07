package shadowsocks

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/ivan-khludov/obscura/internal/domain"
)

// DefaultShadowTLSHandshake is the default TLS handshake imitation target.
const DefaultShadowTLSHandshake = "www.bing.com"

// DefaultShadowTLSHandshakePort is the default handshake server port.
const DefaultShadowTLSHandshakePort = 443

// DefaultObfsPluginOpts is the default obfs-local plugin options.
const DefaultObfsPluginOpts = "obfs=http;obfs-host=www.bing.com"

// Plugins lists supported SIP003 plugins for the create picker.
var Plugins = []string{
	"obfs-local",
	"v2ray-plugin",
}

// TransportModes lists Shadowsocks transport tuning options for the TUI picker.
var TransportModes = []string{
	"Direct",
	"Multiplex",
	"Multiplex (padding)",
	"ShadowTLS",
}

// OptionsGen generates Shadowsocks transport options with optional dependency injection.
type OptionsGen struct {
	RandRead io.Reader
}

func (g *OptionsGen) randReader() io.Reader {
	if g != nil && g.RandRead != nil {
		return g.RandRead
	}
	return rand.Reader
}

// GenerateShadowTLSPassword creates a random base64 password for ShadowTLS v3 users.
func GenerateShadowTLSPassword() (string, error) {
	return (&OptionsGen{}).GenerateShadowTLSPassword()
}

// GenerateShadowTLSPassword creates a random base64 password for ShadowTLS v3 users.
func (g *OptionsGen) GenerateShadowTLSPassword() (string, error) {
	buf := make([]byte, 16)
	if _, err := io.ReadFull(g.randReader(), buf); err != nil {
		return "", fmt.Errorf("generate shadowtls password: %w", err)
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

// GenerateBackendPort picks a localhost port for the Shadowsocks backend behind ShadowTLS.
func GenerateBackendPort(publicPort int) (int, error) {
	return (&OptionsGen{}).GenerateBackendPort(publicPort)
}

// GenerateBackendPort picks a localhost port for the Shadowsocks backend behind ShadowTLS.
func (g *OptionsGen) GenerateBackendPort(publicPort int) (int, error) {
	for range 16 {
		buf := make([]byte, 2)
		if _, err := io.ReadFull(g.randReader(), buf); err != nil {
			return 0, fmt.Errorf("generate backend port: %w", err)
		}
		port := 20000 + (int(buf[0])<<8|int(buf[1]))%30000
		if port != publicPort && port >= 1024 && port <= 65535 {
			return port, nil
		}
	}
	return publicPort + 10000, nil
}

// ValidateOptions checks plugin, multiplex, and ShadowTLS settings in protocol data.
func ValidateOptions(data ProtocolData) error {
	if data.Plugin != "" && !isSupportedPlugin(data.Plugin) {
		return fmt.Errorf("unsupported shadowsocks plugin %q", data.Plugin)
	}
	if data.Plugin != "" && data.PluginOpts == "" {
		return errors.New("plugin_opts is required when plugin is set")
	}
	if data.ShadowTLS && data.Plugin != "" {
		return errors.New("shadowtls and plugin are mutually exclusive")
	}
	if data.ShadowTLS {
		if data.ShadowTLSPassword == "" {
			return errors.New("shadowtls_password is required when shadowtls is enabled")
		}
		if data.ShadowTLSHandshake == "" {
			return errors.New("shadowtls_handshake is required when shadowtls is enabled")
		}
	}
	return nil
}

// isSupportedPlugin reports a configuration property.
func isSupportedPlugin(name string) bool {
	for _, p := range Plugins {
		if p == name {
			return true
		}
	}
	return false
}

// shadowTLSVersion performs an internal helper operation.
func shadowTLSVersion(data ProtocolData) int {
	if data.ShadowTLSVersion == 0 {
		return 3
	}
	return data.ShadowTLSVersion
}

// shadowTLSBackendPort performs an internal helper operation.
func shadowTLSBackendPort(data ProtocolData, publicPort int) int {
	if data.ShadowTLSBackendPort != 0 {
		return data.ShadowTLSBackendPort
	}
	port := publicPort + 10000
	if port > 65535 {
		port = 20000 + publicPort%40000
	}
	return port
}

// shadowTLSHandshakePort performs an internal helper operation.
func shadowTLSHandshakePort(data ProtocolData) int {
	if data.ShadowTLSHandshakePort == 0 {
		return DefaultShadowTLSHandshakePort
	}
	return data.ShadowTLSHandshakePort
}

// applyMultiplex applies transport, TLS preview, or option fields to protocol data.
func applyMultiplex(inbound map[string]any, data ProtocolData) {
	if !data.Multiplex || data.ShadowTLS {
		return
	}
	multiplex := map[string]any{"enabled": true}
	if data.MultiplexPadding {
		multiplex["padding"] = true
	}
	inbound["multiplex"] = multiplex
}

// shadowTLSUsers performs an internal helper operation.
func shadowTLSUsers(clients []domain.ClientConfig, password string) []map[string]string {
	users := make([]map[string]string, 0)
	for _, c := range clients {
		if !c.Enabled {
			continue
		}
		users = append(users, map[string]string{
			"name":     c.Name,
			"password": password,
		})
	}
	return users
}
