// Package render builds sing-box configuration from obscura domain state.
package render

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/store"
)

var _ VPNStore = (*store.Store)(nil)

// DefaultConfigPath is the sing-box config location on a bootstrapped server.
const DefaultConfigPath = domain.DefaultSingBoxConfigPath

// VPNStore loads VPN and client records for rendering.
type VPNStore interface {
	ListEnabledVPNs(ctx context.Context) ([]domain.VPN, error)
	ListClientsByVPN(ctx context.Context, vpnID int64) ([]domain.Client, error)
}

// Renderer merges all enabled VPN inbounds into a single sing-box config.
type Renderer struct {
	store    VPNStore
	registry *protocol.Registry
}

// NewRenderer returns a Renderer backed by store and protocol registry.
func NewRenderer(s VPNStore, reg *protocol.Registry) *Renderer {
	return &Renderer{store: s, registry: reg}
}

// Render generates sing-box JSON without writing to disk.
// It returns an error if any VPN fails validation or no inbounds are produced.
func (r *Renderer) Render(ctx context.Context) ([]byte, error) {
	vpns, err := r.store.ListEnabledVPNs(ctx)
	if err != nil {
		return nil, fmt.Errorf("list vpns: %w", err)
	}
	inbounds := make([]map[string]any, 0, len(vpns))
	endpoints := make([]map[string]any, 0)
	routeRules := make([]map[string]any, 0)
	for _, vpn := range vpns {
		adapter, err := r.registry.Get(vpn.Protocol)
		if err != nil {
			return nil, err
		}
		clients, err := r.store.ListClientsByVPN(ctx, vpn.ID)
		if err != nil {
			return nil, fmt.Errorf("list clients for vpn %q: %w", vpn.Name, err)
		}
		clientConfigs := make([]domain.ClientConfig, len(clients))
		enabledClients := 0
		for i, c := range clients {
			clientConfigs[i] = domain.ClientConfig{
				Name:     c.Name,
				Username: c.Username,
				Password: c.Password,
				Enabled:  c.Enabled,
			}
			if c.Enabled {
				enabledClients++
			}
		}
		if enabledClients == 0 {
			continue
		}
		vpnConfig := domain.VPNConfig{
			Name:         vpn.Name,
			Protocol:     vpn.Protocol,
			Tag:          vpn.Tag,
			Enabled:      vpn.Enabled,
			Listen:       vpn.Listen,
			ProtocolData: vpn.ProtocolData,
		}
		extras, err := adapter.AdditionalInbounds(vpnConfig, clientConfigs)
		if err != nil {
			return nil, fmt.Errorf("extra inbounds vpn %q: %w", vpn.Name, err)
		}
		if len(extras) > 0 {
			inbounds = append(inbounds, extras...)
		}
		if adapter.UsesInbound() {
			inbound, err := adapter.RenderInbound(vpnConfig, clientConfigs)
			if err != nil {
				return nil, fmt.Errorf("render vpn %q: %w", vpn.Name, err)
			}
			inbounds = append(inbounds, inbound)
		}
		renderedEndpoints, err := adapter.RenderEndpoints(vpnConfig, clientConfigs)
		if err != nil {
			return nil, fmt.Errorf("render endpoints vpn %q: %w", vpn.Name, err)
		}
		if len(renderedEndpoints) > 0 {
			endpoints = append(endpoints, renderedEndpoints...)
		}
		rules, err := adapter.RouteExtensions(vpnConfig)
		if err != nil {
			return nil, fmt.Errorf("route extensions vpn %q: %w", vpn.Name, err)
		}
		routeRules = append(routeRules, rules...)
	}
	cfg := Config{
		Log:       LogConfig{Level: "info"},
		Inbounds:  inbounds,
		Outbounds: []Outbound{{Type: "direct", Tag: "direct"}},
		Route:     RouteConfig{Final: "direct", Rules: routeRules},
	}
	if len(endpoints) > 0 {
		cfg.Endpoints = endpoints
	}
	return json.MarshalIndent(cfg, "", "  ")
}
