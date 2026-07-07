package service

import (
	"context"
	"fmt"
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

// closeFirewallPort updates firewall rules for a listen port.
func (s *Service) closeFirewallPort(ctx context.Context, port int, protos []string) {
	if s.firewall == nil || !s.firewall.IsAvailable() {
		return
	}
	for _, ruleSpec := range firewallRuleSpecs(port, protos) {
		if err := s.firewall.DeleteRule(ctx, ruleSpec); err == nil {
			s.manifest.RemoveFirewallRule(ruleSpec)
		}
	}
	_ = s.manifest.Save()
}
