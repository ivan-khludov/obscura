package trojan

import (
	"crypto/ecdh"

	"github.com/ivan-khludov/obscura/internal/protocol"
)

// RenderTLSForTest exposes renderTLS for external test coverage.
func RenderTLSForTest(data ProtocolData) map[string]any {
	return renderTLS(data)
}

// RenderMultiplexForTest exposes renderMultiplex for external test coverage.
func RenderMultiplexForTest(data ProtocolData) map[string]any {
	return renderMultiplex(data)
}

// RenderFallbackForTest exposes renderFallback for external test coverage.
func RenderFallbackForTest(data ProtocolData) (map[string]any, map[string]any) {
	return renderFallback(data)
}

// RenderTransportForTest exposes renderTransport for external test coverage.
func RenderTransportForTest(data ProtocolData) map[string]any {
	return renderTransport(data)
}

// RealityHandshakePortForTest exposes realityHandshakePort for external test coverage.
func RealityHandshakePortForTest(data ProtocolData) int {
	return realityHandshakePort(data)
}

// SetupTLSForTest exposes setupTLS for external test coverage.
func SetupTLSForTest(ctx protocol.BuildContext, data *ProtocolData, tag string, t CreateOptions) error {
	return setupTLS(ctx, data, tag, t)
}

// ApplyPreviewTLSForTest exposes applyPreviewTLS for external test coverage.
func ApplyPreviewTLSForTest(data *ProtocolData, t CreateOptions) {
	applyPreviewTLS(data, t)
}

// BuildCreateProtocolDataForTest exposes buildCreateProtocolData for external test coverage.
func BuildCreateProtocolDataForTest(serverHost string, opts CreateOptions) (ProtocolData, error) {
	return buildCreateProtocolData(serverHost, opts)
}

// ResolveRealityUTLSFingerprintForTest exposes resolveRealityUTLSFingerprint for external tests.
func ResolveRealityUTLSFingerprintForTest(reality bool, fp string) (string, error) {
	return resolveRealityUTLSFingerprint(reality, fp)
}

// ECHServerNameForTest exposes echServerName for external test coverage.
func ECHServerNameForTest(serverName string, acmeDomains []string) string {
	return echServerName(serverName, acmeDomains)
}

// SetTLSGenProviderForTest overrides the TLS generator factory for external tests.
func SetTLSGenProviderForTest(fn func() *TLSGen) func() {
	prev := newTLSGen
	if fn != nil {
		newTLSGen = fn
	}
	return func() {
		newTLSGen = prev
	}
}

// SetNewRealityPrivateKeyForTest overrides X25519 private key construction for external tests.
func SetNewRealityPrivateKeyForTest(fn func([]byte) (*ecdh.PrivateKey, error)) func() {
	prev := newRealityPrivateKey
	if fn != nil {
		newRealityPrivateKey = fn
	}
	return func() {
		newRealityPrivateKey = prev
	}
}

// SetParseProtocolDataHookForTest overrides ParseProtocolData during RenderInbound.
func SetParseProtocolDataHookForTest(fn func([]byte) (ProtocolData, error)) func() {
	old := parseProtocolDataHook
	parseProtocolDataHook = fn
	return func() { parseProtocolDataHook = old }
}

var parseProtocolDataHook func([]byte) (ProtocolData, error)

func parseProtocolDataForRender(raw []byte) (ProtocolData, error) {
	if parseProtocolDataHook != nil {
		return parseProtocolDataHook(raw)
	}
	return ParseProtocolData(raw)
}
