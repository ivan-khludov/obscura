package protocol_test

import (
	"github.com/ivan-khludov/obscura/internal/domain"
)

type stubProtocol struct {
	typ    string
	uri    string
	uriErr error
}

func (s stubProtocol) Type() string { return s.typ }

func (s stubProtocol) ValidateVPN(_ domain.VPNConfig, _ []domain.ClientConfig) error { return nil }

func (s stubProtocol) ValidateClient(_ domain.ClientConfig) error { return nil }

func (s stubProtocol) RenderInbound(_ domain.VPNConfig, _ []domain.ClientConfig) (map[string]any, error) {
	return nil, nil
}

func (s stubProtocol) RenderEndpoints(_ domain.VPNConfig, _ []domain.ClientConfig) ([]map[string]any, error) {
	return nil, nil
}

func (s stubProtocol) AdditionalInbounds(_ domain.VPNConfig, _ []domain.ClientConfig) ([]map[string]any, error) {
	return nil, nil
}

func (s stubProtocol) ClientURI(_ domain.VPNConfig, _ []domain.ClientConfig, _ domain.ClientConfig, _ string) (string, error) {
	return s.uri, s.uriErr
}

func (s stubProtocol) ClientQRContent(_ domain.VPNConfig, _ []domain.ClientConfig, _ domain.ClientConfig, _ string) (string, error) {
	return "", nil
}

func (s stubProtocol) DefaultListen() domain.ListenOptions { return domain.DefaultListenOptions() }

func (s stubProtocol) SupportedListenFields() []string { return nil }

func (s stubProtocol) RouteExtensions(_ domain.VPNConfig) ([]map[string]any, error) { return nil, nil }

func (s stubProtocol) UsesInbound() bool { return true }

func (s stubProtocol) FirewallProtos() []string { return nil }
