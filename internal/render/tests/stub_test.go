package render_test

import (
	"context"
	"errors"

	"github.com/ivan-khludov/obscura/internal/domain"
)

type stubStore struct {
	vpns             []domain.VPN
	clients          map[int64][]domain.Client
	listEnabledErr   error
	listClientsErr   error
	listClientsVPNID int64
}

func (s *stubStore) ListEnabledVPNs(context.Context) ([]domain.VPN, error) {
	if s.listEnabledErr != nil {
		return nil, s.listEnabledErr
	}
	return append([]domain.VPN(nil), s.vpns...), nil
}

func (s *stubStore) ListClientsByVPN(_ context.Context, vpnID int64) ([]domain.Client, error) {
	if s.listClientsErr != nil && vpnID == s.listClientsVPNID {
		return nil, s.listClientsErr
	}
	return append([]domain.Client(nil), s.clients[vpnID]...), nil
}

type testAdapter struct {
	proto        string
	usesInbound  bool
	extras       []map[string]any
	extrasErr    error
	inbound      map[string]any
	inboundErr   error
	endpoints    []map[string]any
	endpointsErr error
	rules        []map[string]any
	rulesErr     error
}

func (a *testAdapter) Type() string { return a.proto }

func (a *testAdapter) ValidateVPN(domain.VPNConfig, []domain.ClientConfig) error { return nil }

func (a *testAdapter) ValidateClient(domain.ClientConfig) error { return nil }

func (a *testAdapter) RenderInbound(domain.VPNConfig, []domain.ClientConfig) (map[string]any, error) {
	if a.inboundErr != nil {
		return nil, a.inboundErr
	}
	if a.inbound != nil {
		return a.inbound, nil
	}
	return map[string]any{"type": "socks", "tag": "in"}, nil
}

func (a *testAdapter) RenderEndpoints(domain.VPNConfig, []domain.ClientConfig) ([]map[string]any, error) {
	if a.endpointsErr != nil {
		return nil, a.endpointsErr
	}
	return append([]map[string]any(nil), a.endpoints...), nil
}

func (a *testAdapter) AdditionalInbounds(domain.VPNConfig, []domain.ClientConfig) ([]map[string]any, error) {
	if a.extrasErr != nil {
		return nil, a.extrasErr
	}
	return append([]map[string]any(nil), a.extras...), nil
}

func (a *testAdapter) ClientURI(domain.VPNConfig, []domain.ClientConfig, domain.ClientConfig, string) (string, error) {
	return "uri://example", nil
}

func (a *testAdapter) ClientQRContent(domain.VPNConfig, []domain.ClientConfig, domain.ClientConfig, string) (string, error) {
	return "uri://example", nil
}

func (a *testAdapter) DefaultListen() domain.ListenOptions {
	return domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080}
}

func (a *testAdapter) SupportedListenFields() []string { return nil }

func (a *testAdapter) RouteExtensions(domain.VPNConfig) ([]map[string]any, error) {
	if a.rulesErr != nil {
		return nil, a.rulesErr
	}
	return append([]map[string]any(nil), a.rules...), nil
}

func (a *testAdapter) UsesInbound() bool { return a.usesInbound }

func (a *testAdapter) FirewallProtos() []string { return nil }

var errStub = errors.New("stub error")

func vpnWithClient(id int64, name, protocol string) (domain.VPN, domain.Client) {
	vpn := domain.VPN{
		ID: id, Name: name, Protocol: protocol, Tag: "vpn-" + name, Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080},
	}
	client := domain.Client{
		ID: 1, VPNID: id, Name: "phone", Username: "phone", Password: "secret", Enabled: true,
	}
	return vpn, client
}
