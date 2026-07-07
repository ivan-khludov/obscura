package service

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/protocol/httpproxy"
)

// createVPN creates a VPN record, opens firewall port when available, and adds
// an initial client when the protocol requires at least one enabled client.
func (s *Service) createVPN(ctx context.Context, in CreateVPNInput) (*CreateVPNResult, error) {
	in = NormalizeCreateVPNInput(in)
	if err := validateCreateVPNInputFields(in); err != nil {
		return nil, err
	}
	adapter, err := s.registry.Get(in.Protocol)
	if err != nil {
		return nil, err
	}
	if in.Listen.Listen == "" {
		in.Listen = adapter.DefaultListen()
	}
	tag := fmt.Sprintf("vpn-%s", sanitizeName(in.Name))
	protocolData, err := s.prepareProtocolData(in, tag)
	if err != nil {
		return nil, err
	}
	if in.Name == "" {
		return nil, fmt.Errorf("vpn name is required")
	}
	vpn := &domain.VPN{
		Name:         in.Name,
		Protocol:     in.Protocol,
		Tag:          tag,
		Enabled:      in.Enabled,
		ClientHost:   domain.NormalizeClientHost(in.ClientHost),
		Listen:       in.Listen,
		ProtocolData: protocolData,
	}
	if err := s.validateVPNListenPort(ctx, in.Listen.ListenPort, 0); err != nil {
		return nil, err
	}
	if err := s.store.CreateVPN(ctx, vpn); err != nil {
		return nil, err
	}
	if s.firewall != nil && s.firewall.IsAvailable() {
		s.openFirewallPort(ctx, vpn.Listen.ListenPort, adapter.FirewallProtos())
	}
	result := &CreateVPNResult{VPN: vpn}
	if !needsInitialClient(adapter, toVPNConfig(vpn)) {
		if in.Enabled {
			if _, err := s.pipeline.Apply(ctx, false); err != nil {
				s.rollbackCreatedVPN(ctx, vpn)
				return nil, fmt.Errorf("apply configuration: %w", err)
			}
		}
		return result, nil
	}
	clientName := in.InitialClientName
	if clientName == "" {
		clientName = "default"
	}
	client, uri, err := s.addClient(ctx, AddClientInput{VPNName: vpn.Name, Name: clientName}, false)
	if err != nil {
		s.rollbackCreatedVPN(ctx, vpn)
		return nil, fmt.Errorf("create initial client: %w", err)
	}
	result.Client = client
	result.URI = uri
	if in.Enabled {
		if _, err := s.pipeline.Apply(ctx, false); err != nil {
			s.rollbackCreatedVPN(ctx, vpn)
			return nil, fmt.Errorf("apply configuration: %w", err)
		}
	}
	return result, nil
}

// rollbackCreatedVPN rolls back partial VPN creation on failure.
func (s *Service) rollbackCreatedVPN(ctx context.Context, vpn *domain.VPN) {
	s.removeVPNCerts(vpn)
	if adapter, err := s.registry.Get(vpn.Protocol); err == nil {
		s.closeFirewallPort(ctx, vpn.Listen.ListenPort, adapter.FirewallProtos())
	}
	_ = s.store.DeleteVPN(ctx, vpn.ID)
}

// prepareProtocolData builds and marshals protocol data for VPN creation.
func (s *Service) prepareProtocolData(in CreateVPNInput, tag string) ([]byte, error) {
	return s.buildProtocolData(in, tag, protocol.BuildModeProvision)
}

// syncFirewallPort synchronizes runtime state with persistent configuration.
func (s *Service) syncFirewallPort(ctx context.Context, vpn *domain.VPN, oldPort, newPort int) error {
	if oldPort == newPort || s.firewall == nil || !s.firewall.IsAvailable() {
		return nil
	}
	adapter, err := s.registry.Get(vpn.Protocol)
	if err != nil {
		return err
	}
	protos := adapter.FirewallProtos()
	s.closeFirewallPort(ctx, oldPort, protos)
	for _, ruleSpec := range firewallRuleSpecs(newPort, protos) {
		proto := strings.TrimPrefix(ruleSpec, fmt.Sprintf("%d/", newPort))
		rule, err := s.firewall.AllowPort(ctx, newPort, proto)
		if err != nil {
			return fmt.Errorf("open firewall port %d/%s: %w", newPort, proto, err)
		}
		s.manifest.AddFirewallRule(rule)
	}
	_ = s.manifest.Save()
	return nil
}

// updateVPN updates an existing VPN and reapplies configuration when requested.
func (s *Service) updateVPN(ctx context.Context, name string, in UpdateVPNInput, reapply bool) (*domain.VPN, error) {
	vpn, err := s.store.GetVPNByName(ctx, name)
	if err != nil {
		return nil, err
	}
	oldPort := vpn.Listen.ListenPort
	if in.Name != nil {
		if strings.TrimSpace(*in.Name) == "" {
			return nil, fmt.Errorf("vpn name is required")
		}
		vpn.Name = *in.Name
	}
	if in.Listen != nil {
		if err := s.validateVPNListenPort(ctx, in.Listen.ListenPort, vpn.ID); err != nil {
			return nil, err
		}
		vpn.Listen = *in.Listen
	}
	if in.ClientHost != nil {
		clientHost := domain.NormalizeClientHost(*in.ClientHost)
		if err := domain.ValidateClientHost(clientHost); err != nil {
			return nil, err
		}
		vpn.ClientHost = clientHost
	}
	if in.Enabled != nil {
		vpn.Enabled = *in.Enabled
	}
	if in.HTTPTLS != nil {
		if vpn.Protocol != "http" {
			return nil, fmt.Errorf("tls is only supported for http protocol")
		}
		data, err := httpproxy.ParseProtocolData(vpn.ProtocolData)
		if err != nil {
			return nil, err
		}
		switch {
		case *in.HTTPTLS && !data.TLS:
			if err := s.enableHTTPTLS(vpn); err != nil {
				return nil, err
			}
		case !*in.HTTPTLS && data.TLS:
			s.disableHTTPTLS(vpn)
		}
	}
	adapter, err := s.registry.Get(vpn.Protocol)
	if err != nil {
		return nil, err
	}
	clients, err := s.store.ListClientsByVPN(ctx, vpn.ID)
	if err != nil {
		return nil, err
	}
	clientConfigs := toClientConfigs(clients)
	vpnConfig := toVPNConfig(vpn)
	if err := adapter.ValidateVPN(vpnConfig, clientConfigs); err != nil {
		return nil, err
	}
	if err := s.syncFirewallPort(ctx, vpn, oldPort, vpn.Listen.ListenPort); err != nil {
		return nil, err
	}
	if err := s.store.UpdateVPN(ctx, vpn); err != nil {
		return nil, err
	}
	if reapply {
		if _, err := s.pipeline.Apply(ctx, false); err != nil {
			return nil, err
		}
	}
	return vpn, nil
}

// deleteVPN removes a VPN and its clients, then reapplies configuration.
func (s *Service) deleteVPN(ctx context.Context, name string) error {
	vpn, err := s.store.GetVPNByName(ctx, name)
	if err != nil {
		return err
	}
	adapter, err := s.registry.Get(vpn.Protocol)
	if err != nil {
		return err
	}
	s.closeFirewallPort(ctx, vpn.Listen.ListenPort, adapter.FirewallProtos())
	if err := s.store.DeleteVPN(ctx, vpn.ID); err != nil {
		return err
	}
	_, err = s.pipeline.Apply(ctx, false)
	return err
}

// listVPNs returns all VPN records sorted by listen port, then name.
func (s *Service) listVPNs(ctx context.Context) ([]domain.VPN, error) {
	vpns, err := s.store.ListVPNs(ctx)
	if err != nil {
		return nil, err
	}
	sort.Slice(vpns, func(i, j int) bool {
		if vpns[i].Listen.ListenPort != vpns[j].Listen.ListenPort {
			return vpns[i].Listen.ListenPort < vpns[j].Listen.ListenPort
		}
		return vpns[i].Name < vpns[j].Name
	})
	return vpns, nil
}

// getVPN returns a VPN by name.
func (s *Service) getVPN(ctx context.Context, name string) (*domain.VPN, error) {
	return s.store.GetVPNByName(ctx, name)
}
