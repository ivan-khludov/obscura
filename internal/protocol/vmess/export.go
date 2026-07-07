package vmess

import (
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
)

// SetParseProtocolDataHookForTest overrides ParseProtocolData during tests.
func SetParseProtocolDataHookForTest(fn func([]byte) (ProtocolData, error)) func() {
	prev := parseProtocolDataHook
	parseProtocolDataHook = fn
	return func() { parseProtocolDataHook = prev }
}

// SetUsersFromClientsHookForTest overrides UsersFromClients during tests.
func SetUsersFromClientsHookForTest(fn func(ProtocolData, []domain.ClientConfig) ([]map[string]any, error)) func() {
	prev := usersFromClientsHook
	usersFromClientsHook = fn
	return func() { usersFromClientsHook = prev }
}

// SetJSONMarshalHookForTest overrides json.Marshal during buildShareLink tests.
func SetJSONMarshalHookForTest(fn func(any) ([]byte, error)) func() {
	prev := jsonMarshal
	if fn != nil {
		jsonMarshal = fn
	}
	return func() { jsonMarshal = prev }
}

// SetTLSGenFactoryForTest replaces TLS generation during BuildProtocolData.
func SetTLSGenFactoryForTest(fn func() *TLSGen) func() {
	prev := tlsGenFactory
	if fn != nil {
		tlsGenFactory = fn
	}
	return func() { tlsGenFactory = prev }
}

// BuildCreateProtocolDataForTest exposes buildCreateProtocolData for external test coverage.
func BuildCreateProtocolDataForTest(serverHost string, v CreateOptions) (ProtocolData, error) {
	return buildCreateProtocolData(serverHost, v)
}

// ApplyPreviewTLSForTest exposes applyPreviewTLS for external test coverage.
func ApplyPreviewTLSForTest(data *ProtocolData, v CreateOptions) {
	applyPreviewTLS(data, v)
}

// ApplyTransportForTest exposes applyTransport for external test coverage.
func ApplyTransportForTest(data *ProtocolData, v CreateOptions) error {
	return applyTransport(data, v)
}

// SetupTLSForTest exposes setupTLS for external test coverage.
func SetupTLSForTest(ctx protocol.BuildContext, data *ProtocolData, tag string, v CreateOptions) error {
	return setupTLS(ctx, data, tag, v)
}

// SetupECHForTest exposes setupECH for external test coverage.
func SetupECHForTest(ctx protocol.BuildContext, data *ProtocolData, tag string) error {
	return setupECH(ctx, data, tag)
}

// ResolveRealityUTLSFingerprintForTest exposes resolveRealityUTLSFingerprint for external test coverage.
func ResolveRealityUTLSFingerprintForTest(reality bool, fp string) (string, error) {
	return resolveRealityUTLSFingerprint(reality, fp)
}

// EchServerNameForTest exposes echServerName for external test coverage.
func EchServerNameForTest(serverName string, acmeDomains []string) string {
	return echServerName(serverName, acmeDomains)
}

// RenderMultiplexForTest exposes renderMultiplex for external test coverage.
func RenderMultiplexForTest(data ProtocolData) map[string]any {
	return renderMultiplex(data)
}

// RealityHandshakePortForTest exposes realityHandshakePort for external test coverage.
func RealityHandshakePortForTest(data ProtocolData) int {
	return realityHandshakePort(data)
}

// ClientAlterIDForTest exposes clientAlterID for external test coverage.
func ClientAlterIDForTest(data ProtocolData, client domain.ClientConfig) (int, error) {
	return clientAlterID(data, client)
}

// BuildShareLinkForTest exposes buildShareLink for external test coverage.
func BuildShareLinkForTest(vpn domain.VPNConfig, data ProtocolData, client domain.ClientConfig, serverHost string) (string, error) {
	return buildShareLink(vpn, data, client, serverHost)
}

// ShareNetTypeForTest exposes shareNetType for external test coverage.
func ShareNetTypeForTest(data ProtocolData) string {
	return shareNetType(data)
}
