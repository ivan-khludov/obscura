package hysteria2

import (
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
func BuildCreateProtocolDataForTest(serverHost string, opts CreateOptions) (ProtocolData, error) {
	return buildCreateProtocolData(serverHost, opts)
}

// ApplyPreviewTLSForTest exposes applyPreviewTLS for external test coverage.
func ApplyPreviewTLSForTest(data *ProtocolData, h CreateOptions) {
	applyPreviewTLS(data, h)
}

// EchServerNameForTest exposes echServerName for external test coverage.
func EchServerNameForTest(serverName string, acmeDomains []string) string {
	return echServerName(serverName, acmeDomains)
}

// RenderTLSForTest exposes renderTLS for external test coverage.
func RenderTLSForTest(data ProtocolData) map[string]any {
	return renderTLS(data)
}

// RenderObfsForTest exposes renderObfs for external test coverage.
func RenderObfsForTest(data ProtocolData) map[string]any {
	return renderObfs(data)
}

// RenderMasqueradeForTest exposes renderMasquerade for external test coverage.
func RenderMasqueradeForTest(data ProtocolData) any {
	return renderMasquerade(data)
}

// RenderRealmForTest exposes renderRealm for external test coverage.
func RenderRealmForTest(r *RealmOptions) map[string]any {
	return renderRealm(r)
}

// ApplyQUICFieldsForTest exposes applyQUICFields for external test coverage.
func ApplyQUICFieldsForTest(target map[string]any, data ProtocolData) {
	applyQUICFields(target, data)
}

// SetupTLSForTest exposes setupTLS for external test coverage.
func SetupTLSForTest(ctx protocol.BuildContext, data *ProtocolData, tag string, h CreateOptions) error {
	return setupTLS(ctx, data, tag, h)
}

// SetupECHForTest exposes setupECH for external test coverage.
func SetupECHForTest(ctx protocol.BuildContext, data *ProtocolData, tag string) error {
	return setupECH(ctx, data, tag)
}

// BuildMasqueradeObjectForTest exposes buildMasqueradeObject for external test coverage.
func BuildMasqueradeObjectForTest(h CreateOptions) (*MasqueradeObject, error) {
	return buildMasqueradeObject(h)
}

// ValidateMasqueradeObjectForTest exposes validateMasqueradeObject for external test coverage.
func ValidateMasqueradeObjectForTest(m MasqueradeObject) error {
	return validateMasqueradeObject(m)
}

// ValidateRealmForTest exposes validateRealm for external test coverage.
func ValidateRealmForTest(r RealmOptions) error {
	return validateRealm(r)
}
