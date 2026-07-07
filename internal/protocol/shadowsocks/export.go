package shadowsocks

import "github.com/ivan-khludov/obscura/internal/protocol"

// BuildCreateProtocolDataForTest exposes buildCreateProtocolData for external test coverage.
func BuildCreateProtocolDataForTest(opts CreateOptions, mode protocol.BuildMode) (ProtocolData, error) {
	return buildCreateProtocolData(opts, mode)
}

// ShadowTLSBackendPortForTest exposes shadowTLSBackendPort for external test coverage.
func ShadowTLSBackendPortForTest(data ProtocolData, publicPort int) int {
	return shadowTLSBackendPort(data, publicPort)
}

// ShadowTLSVersionForTest exposes shadowTLSVersion for external test coverage.
func ShadowTLSVersionForTest(data ProtocolData) int {
	return shadowTLSVersion(data)
}

// ShadowTLSHandshakePortForTest exposes shadowTLSHandshakePort for external test coverage.
func ShadowTLSHandshakePortForTest(data ProtocolData) int {
	return shadowTLSHandshakePort(data)
}

// SetGenProvidersForTest overrides key/options generators for external tests.
func SetGenProvidersForTest(keyGen func() *KeyGen, optsGen func() *OptionsGen) func() {
	prevKey, prevOpts := newKeyGen, newOptionsGen
	if keyGen != nil {
		newKeyGen = keyGen
	}
	if optsGen != nil {
		newOptionsGen = optsGen
	}
	return func() {
		newKeyGen, newOptionsGen = prevKey, prevOpts
	}
}

// SetParseProtocolDataForTest overrides ParseProtocolData for external tests.
func SetParseProtocolDataForTest(fn func([]byte) (ProtocolData, error)) func() {
	prev := parseProtocolData
	if fn != nil {
		parseProtocolData = fn
	}
	return func() {
		parseProtocolData = prev
	}
}
