package tuic

import (
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
)

// SetTLSGenFactoryForTest overrides TLSGen creation.
func SetTLSGenFactoryForTest(fn func() *TLSGen) func() {
	prev := newTLSGen
	if fn != nil {
		newTLSGen = fn
	}
	return func() {
		newTLSGen = prev
	}
}

// SetParseProtocolDataHookForTest overrides ParseProtocolData during adapter operations.
func SetParseProtocolDataHookForTest(fn func([]byte) (ProtocolData, error)) func() {
	prev := parseProtocolData
	if fn != nil {
		parseProtocolData = fn
	}
	return func() {
		parseProtocolData = prev
	}
}

// BuildCreateProtocolDataForTest exposes buildCreateProtocolData for external test coverage.
func BuildCreateProtocolDataForTest(serverHost string, opts CreateOptions) ProtocolData {
	return buildCreateProtocolData(serverHost, opts)
}

// ApplyPreviewTLSForTest exposes applyPreviewTLS for external test coverage.
func ApplyPreviewTLSForTest(data *ProtocolData, t CreateOptions) {
	applyPreviewTLS(data, t)
}

// EchServerNameForTest exposes echServerName for external test coverage.
func EchServerNameForTest(serverName string, acmeDomains []string) string {
	return echServerName(serverName, acmeDomains)
}

// RenderTLSForTest exposes renderTLS for external test coverage.
func RenderTLSForTest(data ProtocolData) map[string]any {
	return renderTLS(data)
}

// ApplyQUICFieldsForTest exposes applyQUICFields for external test coverage.
func ApplyQUICFieldsForTest(target map[string]any, data ProtocolData) {
	applyQUICFields(target, data)
}

// SetupTLSForTest exposes setupTLS for external test coverage.
func SetupTLSForTest(ctx protocol.BuildContext, data *ProtocolData, tag string, t CreateOptions) error {
	return setupTLS(ctx, data, tag, t)
}

// SetupECHForTest exposes setupECH for external test coverage.
func SetupECHForTest(ctx protocol.BuildContext, data *ProtocolData, tag string) error {
	return setupECH(ctx, data, tag)
}

// UsersFromClientsForTest exposes UsersFromClients for external test coverage.
func UsersFromClientsForTest(clients []domain.ClientConfig) []map[string]string {
	return UsersFromClients(clients)
}
