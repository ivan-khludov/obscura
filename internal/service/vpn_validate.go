package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/go-cmp/cmp"

	"github.com/ivan-khludov/obscura/internal/domain"
)

// ValidateVPNName checks that a VPN name is non-empty and not already taken.
func (s *Service) ValidateVPNName(ctx context.Context, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("vpn name is required")
	}
	_, err := s.store.GetVPNByName(ctx, name)
	if err == nil {
		return fmt.Errorf("vpn %q already exists", name)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return nil
}

// ValidateVPNListenPort checks port uniqueness among VPNs and SSH reservation.
func (s *Service) ValidateVPNListenPort(ctx context.Context, port int) error {
	return s.validateVPNListenPort(ctx, port, 0)
}

// ValidateCreateVPNDraft runs pre-create checks without writing to the database.
func (s *Service) ValidateCreateVPNDraft(ctx context.Context, in CreateVPNInput) error {
	in = NormalizeCreateVPNInput(in)
	if err := validateCreateVPNInputFields(in); err != nil {
		return err
	}
	if err := s.ValidateVPNName(ctx, in.Name); err != nil {
		return err
	}
	adapter, err := s.registry.Get(in.Protocol)
	if err != nil {
		return err
	}
	listen := in.Listen
	if listen.Listen == "" {
		listen = adapter.DefaultListen()
	}
	if err := s.ValidateVPNListenPort(ctx, listen.ListenPort); err != nil {
		return err
	}
	tag := fmt.Sprintf("vpn-%s", sanitizeName(in.Name))
	protocolData, err := s.buildProtocolDataPreview(in, tag)
	if err != nil {
		return err
	}
	vpnConfig := toVPNConfig(&domain.VPN{
		Name:         in.Name,
		Protocol:     in.Protocol,
		Tag:          tag,
		Enabled:      in.Enabled,
		ClientHost:   domain.NormalizeClientHost(in.ClientHost),
		Listen:       listen,
		ProtocolData: protocolData,
	})
	if err := adapter.ValidateVPN(vpnConfig, nil); err != nil {
		if !strings.Contains(err.Error(), "client") {
			return err
		}
	}
	return nil
}

// WizardValidateStep marks which create-VPN wizard step just completed.
type WizardValidateStep int

// Wizard validation steps after each wizard screen.
const (
	WizardAfterPort WizardValidateStep = iota
	WizardAfterSNI
	WizardAfterVlessFlow
	WizardAfterTransport
	WizardAfterTransportDetail
	WizardAfterFallback
	WizardAfterHy2Bandwidth
	WizardAfterHy2Masquerade
	WizardAfterWireguardSubnet
	WizardAfterWireguardMTU
	WizardComplete
)

// ValidateCreateVPNWizardStep validates create input at a wizard checkpoint.
func (s *Service) ValidateCreateVPNWizardStep(ctx context.Context, in CreateVPNInput, step WizardValidateStep) error {
	in = NormalizeCreateVPNInput(in)
	if err := validateCreateVPNInputFields(in); err != nil {
		return err
	}
	switch step {
	case WizardAfterPort:
		if in.Name != "" {
			if err := s.ValidateVPNName(ctx, in.Name); err != nil {
				return err
			}
		}
		if in.Listen.ListenPort > 0 {
			if err := s.ValidateVPNListenPort(ctx, in.Listen.ListenPort); err != nil {
				return err
			}
		}
		return nil
	case WizardAfterSNI, WizardAfterVlessFlow:
		return s.validateCreateVPNProtocolPreview(ctx, in)
	case WizardAfterTransport:
		return s.validateCreateVPNProtocolPreview(ctx, in)
	case WizardAfterTransportDetail, WizardAfterFallback,
		WizardAfterHy2Bandwidth, WizardAfterHy2Masquerade,
		WizardAfterWireguardSubnet, WizardAfterWireguardMTU:
		return s.validateCreateVPNProtocolPreview(ctx, in)
	case WizardComplete:
		return s.ValidateCreateVPNDraft(ctx, in)
	default:
		return nil
	}
}

// validateCreateVPNInputFields validates protocol options or configuration consistency.
func validateCreateVPNInputFields(in CreateVPNInput) error {
	in = NormalizeCreateVPNInput(in)
	if in.HTTPTLS && in.Protocol != string(domain.ProtocolHTTP) {
		return fmt.Errorf("tls is only supported for http protocol")
	}
	if in.SSMethod != "" && in.Protocol != string(domain.ProtocolShadowsocks) {
		return fmt.Errorf("method is only supported for shadowsocks protocol")
	}
	if ssOptionSet(in) && in.Protocol != string(domain.ProtocolShadowsocks) {
		return fmt.Errorf("shadowsocks transport options are only supported for shadowsocks protocol")
	}
	if err := validateStructuredProtocolOptionOwnership(in); err != nil {
		return err
	}
	return domain.ValidateClientHost(domain.NormalizeClientHost(in.ClientHost))
}

func validateStructuredProtocolOptionOwnership(in CreateVPNInput) error {
	selected := domain.ProtocolType(in.Protocol)
	checks := []struct {
		protocol domain.ProtocolType
		has      bool
		label    string
	}{
		{protocol: domain.ProtocolHTTP, has: hasHTTPOptions(in.HTTP), label: "http"},
		{protocol: domain.ProtocolShadowsocks, has: hasShadowsocksOptions(in.Shadowsocks), label: "shadowsocks"},
		{protocol: domain.ProtocolTrojan, has: !cmp.Equal(in.Trojan, TrojanCreateOptions{}), label: "trojan"},
		{protocol: domain.ProtocolWireGuard, has: !cmp.Equal(in.Wireguard, WireguardCreateOptions{}), label: "wireguard"},
		{protocol: domain.ProtocolVMess, has: !cmp.Equal(in.VMess, VMessCreateOptions{}), label: "vmess"},
		{protocol: domain.ProtocolVLESS, has: !cmp.Equal(in.VLESS, VLESSCreateOptions{}), label: "vless"},
		{protocol: domain.ProtocolHysteria2, has: !cmp.Equal(in.Hysteria2, Hysteria2CreateOptions{}), label: "hysteria2"},
		{protocol: domain.ProtocolTUIC, has: !cmp.Equal(in.TUIC, TUICCreateOptions{}), label: "tuic"},
	}
	for _, check := range checks {
		if !check.has || check.protocol == selected {
			continue
		}
		return fmt.Errorf("%s options are only supported for %s protocol", check.label, check.protocol)
	}
	return nil
}

// validateCreateVPNProtocolPreview validates protocol options or configuration consistency.
func (s *Service) validateCreateVPNProtocolPreview(_ context.Context, in CreateVPNInput) error {
	if in.Protocol == "" {
		return nil
	}
	in = NormalizeCreateVPNInput(in)
	adapter, err := s.registry.Get(in.Protocol)
	if err != nil {
		return err
	}
	tag := previewTag(in.Name)
	protocolData, err := s.buildProtocolDataPreview(in, tag)
	if err != nil {
		return err
	}
	listen := in.Listen
	if listen.Listen == "" {
		listen = adapter.DefaultListen()
	}
	vpnConfig := toVPNConfig(&domain.VPN{
		Name:         previewName(in.Name),
		Protocol:     in.Protocol,
		Tag:          tag,
		Enabled:      in.Enabled,
		ClientHost:   domain.NormalizeClientHost(in.ClientHost),
		Listen:       listen,
		ProtocolData: protocolData,
	})
	if err := adapter.ValidateVPN(vpnConfig, nil); err != nil {
		if strings.Contains(err.Error(), "client") {
			return nil
		}
		return err
	}
	return nil
}

// previewTag builds protocol data for validation without provisioning TLS assets.
func previewTag(name string) string {
	if name == "" {
		return "vpn-preview"
	}
	return fmt.Sprintf("vpn-%s", sanitizeName(name))
}

// previewName builds protocol data for validation without provisioning TLS assets.
func previewName(name string) string {
	if name == "" {
		return "preview"
	}
	return name
}
