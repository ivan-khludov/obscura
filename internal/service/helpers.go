package service

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"strings"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
)

// PasswordGen generates URL-safe passwords with optional dependency injection.
type PasswordGen struct {
	RandRead io.Reader
}

func (g *PasswordGen) randReader() io.Reader {
	if g != nil && g.RandRead != nil {
		return g.RandRead
	}
	return rand.Reader
}

// needsInitialClient reports whether a protocol or VPN uses a feature.
func needsInitialClient(adapter protocol.Protocol, vpn domain.VPNConfig) bool {
	if builder, ok := adapter.(protocol.DataBuilder); ok {
		return builder.NeedsInitialClient(vpn)
	}
	err := adapter.ValidateVPN(vpn, nil)
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "client")
}

// toVPNConfig converts a stored VPN record into a protocol adapter input.
func toVPNConfig(vpn *domain.VPN) domain.VPNConfig {
	return domain.VPNConfig{
		Name: vpn.Name, Protocol: vpn.Protocol, Tag: vpn.Tag,
		Enabled: vpn.Enabled, ClientHost: vpn.ClientHost, Listen: vpn.Listen, ProtocolData: vpn.ProtocolData,
	}
}

// toClientConfigs converts stored client records into protocol adapter inputs.
func toClientConfigs(clients []domain.Client) []domain.ClientConfig {
	out := make([]domain.ClientConfig, len(clients))
	for i, c := range clients {
		out[i] = domain.ClientConfig{Name: c.Name, Username: c.Username, Password: c.Password, Enabled: c.Enabled}
	}
	return out
}

// ssOptionSet reports whether create input sets protocol-specific options.
func ssOptionSet(in CreateVPNInput) bool {
	return in.SSPlugin != "" || in.SSPluginOpts != "" || in.SSMultiplex ||
		in.SSMultiplexPadding || in.SSShadowTLS || in.SSShadowTLSHandshake != "" ||
		in.SSShadowTLSHandshakePort != 0 || in.SSShadowTLSStrictMode
}

// sanitizeName normalizes a user-provided name into a URL-safe slug.
func sanitizeName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.ReplaceAll(name, " ", "-")
	return name
}

// randomPassword generates a URL-safe random password of length n.
func (g *PasswordGen) randomPassword(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(g.randReader(), buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf)[:n], nil
}
