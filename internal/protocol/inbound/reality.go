package inbound

import (
	"errors"

	"github.com/ivan-khludov/obscura/internal/protocol"
)

// RealityParams carries the fields needed to render or validate a sing-box
// Reality TLS handshake fragment.
type RealityParams struct {
	PrivateKey        string
	ShortIDs          []string
	HandshakeServer   string
	HandshakePort     int
	MaxTimeDifference string
	UTLSFingerprint   string
}

// RenderReality builds the sing-box "reality" TLS fragment.
func RenderReality(p RealityParams) map[string]any {
	reality := map[string]any{
		"enabled":     true,
		"private_key": p.PrivateKey,
		"short_id":    p.ShortIDs,
		"handshake": map[string]any{
			"server":      p.HandshakeServer,
			"server_port": p.HandshakePort,
		},
	}
	if p.MaxTimeDifference != "" {
		reality["max_time_difference"] = p.MaxTimeDifference
	}
	return reality
}

// ValidateReality checks Reality field consistency when Reality is enabled.
// It is a no-op when enabled is false.
func ValidateReality(enabled bool, p RealityParams) error {
	if !enabled {
		return nil
	}
	if p.PrivateKey == "" {
		return errors.New("reality_private_key is required when reality is enabled")
	}
	if len(p.ShortIDs) == 0 {
		return errors.New("reality_short_id is required when reality is enabled")
	}
	if p.HandshakeServer == "" {
		return errors.New("reality_handshake_server is required when reality is enabled")
	}
	return protocol.ValidateRealityUTLSFingerprint(p.UTLSFingerprint)
}
