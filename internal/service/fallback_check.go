package service

import (
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/fallback"
	"github.com/ivan-khludov/obscura/internal/protocol/trojan"
)

// usesLocalFallbackStub reports whether a protocol or VPN uses a feature.
func usesLocalFallbackStub(vpn domain.VPN) bool {
	switch vpn.Protocol {
	case "trojan":
		data, err := trojan.ParseProtocolData(vpn.ProtocolData)
		if err != nil {
			return false
		}
		return data.FallbackServer == fallback.DefaultServer && data.FallbackPort == fallback.DefaultPort
	default:
		return false
	}
}
