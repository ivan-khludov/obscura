package socks5

import (
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
)

// BuildProtocolData builds SOCKS5 protocol data.
func (a *Adapter) BuildProtocolData(_ protocol.BuildContext, _ domain.CreateVPNSpec, _ string, _ protocol.BuildMode) ([]byte, error) {
	return []byte("{}"), nil
}

// NeedsInitialClient reports whether SOCKS5 requires an enabled client.
func (a *Adapter) NeedsInitialClient(_ domain.VPNConfig) bool {
	return true
}
