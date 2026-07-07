// Package inbound provides shared helpers for TLS inbound protocols.
package inbound

// FallbackTarget is a sing-box fallback server endpoint.
type FallbackTarget struct {
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
}

// RenderFallback builds sing-box fallback and fallback_for_alpn maps.
func RenderFallback(server string, port int, forALPN map[string]FallbackTarget) (map[string]any, map[string]any) {
	var fallback map[string]any
	if server != "" && port != 0 {
		fallback = map[string]any{
			"server":      server,
			"server_port": port,
		}
	}
	var fallbackForALPN map[string]any
	if len(forALPN) > 0 {
		fallbackForALPN = make(map[string]any, len(forALPN))
		for alpn, target := range forALPN {
			fallbackForALPN[alpn] = map[string]any{
				"server":      target.Server,
				"server_port": target.ServerPort,
			}
		}
	}
	return fallback, fallbackForALPN
}
