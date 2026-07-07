package inbound

// RenderMultiplex builds the sing-box "multiplex" fragment. Brutal congestion
// control is only rendered when brutal is true; protocols that do not support
// brutal (e.g. trojan) simply pass false.
func RenderMultiplex(padding, brutal bool, brutalUpMbps, brutalDownMbps int) map[string]any {
	multiplex := map[string]any{"enabled": true}
	if padding {
		multiplex["padding"] = true
	}
	if brutal {
		multiplex["brutal"] = map[string]any{
			"enabled":   true,
			"up_mbps":   brutalUpMbps,
			"down_mbps": brutalDownMbps,
		}
	}
	return multiplex
}
