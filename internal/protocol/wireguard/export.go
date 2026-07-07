package wireguard

import "github.com/ivan-khludov/obscura/internal/domain"

// RenderPeersForTest exposes renderPeers for external test coverage.
func RenderPeersForTest(data ProtocolData, clients []domain.ClientConfig) ([]map[string]any, error) {
	return renderPeers(data, clients)
}

// ClientPublicKeyErrorForTest returns errClientPublicKey for Error() coverage.
func ClientPublicKeyErrorForTest(name string) error {
	return errClientPublicKey(name)
}

// SetKeyGenFactoryForTest replaces key generation during BuildProtocolData.
func SetKeyGenFactoryForTest(fn func() *KeyGen) func() {
	old := keyGenFactory
	keyGenFactory = fn
	return func() { keyGenFactory = old }
}

// SetPublicKeyFromPrivateFuncForTest replaces public key derivation.
func SetPublicKeyFromPrivateFuncForTest(fn func(string) (string, error)) func() {
	old := publicKeyFromPrivateFunc
	publicKeyFromPrivateFunc = fn
	return func() { publicKeyFromPrivateFunc = old }
}

// SetParseProtocolDataHookForTest replaces ParseProtocolData behavior.
func SetParseProtocolDataHookForTest(fn func([]byte) (ProtocolData, error)) func() {
	old := parseProtocolDataHook
	parseProtocolDataHook = fn
	return func() { parseProtocolDataHook = old }
}

// ParseProtocolDataUnhooked parses protocol data without test hooks.
func ParseProtocolDataUnhooked(raw []byte) (ProtocolData, error) {
	return parseProtocolData(raw)
}
