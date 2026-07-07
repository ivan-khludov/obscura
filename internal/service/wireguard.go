package service

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/ivan-khludov/obscura/internal/protocol/wireguard"
)

// WireguardCreateOptions holds wireguard-specific create parameters.
type WireguardCreateOptions = wireguard.CreateOptions

// WireguardKeyGen generates WireGuard keypairs with optional dependency injection.
type WireguardKeyGen struct {
	GenerateKeypair func() (wireguard.Keypair, error)
}

func (g WireguardKeyGen) keypair() (wireguard.Keypair, error) {
	if g.GenerateKeypair != nil {
		return g.GenerateKeypair()
	}
	return wireguard.GenerateKeypair()
}

// generateWireguardClientCredentials generates keys, passwords, or identifiers.
func (s *Service) generateWireguardClientCredentials() (username, password string, err error) {
	pair, err := s.wireguardKeyGen.keypair()
	if err != nil {
		return "", "", err
	}
	return pair.PublicKey, pair.PrivateKey, nil
}

// firewallRuleSpecs builds or applies firewall rule specifications.
func firewallRuleSpecs(port int, protos []string) []string {
	rules := make([]string, 0, len(protos))
	for _, proto := range protos {
		proto = strings.TrimSpace(proto)
		if proto == "" {
			continue
		}
		rules = append(rules, fmt.Sprintf("%d/%s", port, proto))
	}
	return rules
}

// firewallRulePort parses the port from a firewall rule spec like "443/tcp".
func firewallRulePort(spec string) (int, bool) {
	spec = strings.TrimSpace(spec)
	portStr := spec
	if idx := strings.IndexByte(spec, '/'); idx >= 0 {
		portStr = spec[:idx]
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, false
	}
	return port, true
}

// isSSHFirewallRule reports whether a firewall rule spec targets the SSH port.
func isSSHFirewallRule(spec string, sshPort int) bool {
	port, ok := firewallRulePort(spec)
	return ok && port == sshPort
}

// openFirewallPort updates firewall rules for a listen port.
func (s *Service) openFirewallPort(ctx context.Context, port int, protos []string) {
	if s.firewall == nil || !s.firewall.IsAvailable() {
		return
	}
	for _, ruleSpec := range firewallRuleSpecs(port, protos) {
		proto := strings.TrimPrefix(ruleSpec, fmt.Sprintf("%d/", port))
		rule, err := s.firewall.AllowPort(ctx, port, proto)
		if err == nil {
			s.manifest.AddFirewallRule(rule)
		}
	}
	_ = s.manifest.Save()
}

// ensureSSHFirewallAllowed re-asserts the SSH allow rule so that any ufw
// mutation (which reloads the whole ruleset) can never leave the SSH port
// without an allow rule and drop the controlling session. The ufw allow
// command is idempotent, so calling this repeatedly is safe.
func (s *Service) ensureSSHFirewallAllowed(ctx context.Context) {
	if s.firewall == nil || !s.firewall.IsAvailable() {
		return
	}
	rule, err := s.firewall.AllowPort(ctx, s.SSHPort(), "tcp")
	if err == nil {
		s.manifest.AddFirewallRule(rule)
	}
}

// closeFirewallPort updates firewall rules for a listen port.
func (s *Service) closeFirewallPort(ctx context.Context, port int, protos []string) {
	if s.firewall == nil || !s.firewall.IsAvailable() {
		return
	}
	// Guarantee SSH stays reachable across the ufw reload triggered by DeleteRule.
	s.ensureSSHFirewallAllowed(ctx)
	sshPort := s.SSHPort()
	for _, ruleSpec := range firewallRuleSpecs(port, protos) {
		// Never delete the SSH port rule, even if manifest state is out of sync.
		if port == sshPort {
			continue
		}
		if err := s.firewall.DeleteRule(ctx, ruleSpec); err == nil {
			s.manifest.RemoveFirewallRule(ruleSpec)
		}
	}
	_ = s.manifest.Save()
}
