package inbound

// HTTP2Options holds HTTP2 tuning fields embedded in QUIC inbound options
// (hysteria2, tuic).
type HTTP2Options struct {
	IdleTimeout             string `json:"idle_timeout,omitempty"`
	KeepAlivePeriod         string `json:"keep_alive_period,omitempty"`
	StreamReceiveWindow     string `json:"stream_receive_window,omitempty"`
	ConnectionReceiveWindow string `json:"connection_receive_window,omitempty"`
	MaxConcurrentStreams    int    `json:"max_concurrent_streams,omitempty"`
}

// ApplyQUICFields merges shared QUIC inbound tuning fields (packet size, MTU
// discovery, HTTP2 fields) into an already-built sing-box inbound fragment.
func ApplyQUICFields(target map[string]any, http2 *HTTP2Options, initialPacketSize int, disablePathMTUDiscovery bool) {
	if initialPacketSize > 0 {
		target["initial_packet_size"] = initialPacketSize
	}
	if disablePathMTUDiscovery {
		target["disable_path_mtu_discovery"] = true
	}
	if http2 == nil {
		return
	}
	if http2.IdleTimeout != "" {
		target["idle_timeout"] = http2.IdleTimeout
	}
	if http2.KeepAlivePeriod != "" {
		target["keep_alive_period"] = http2.KeepAlivePeriod
	}
	if http2.StreamReceiveWindow != "" {
		target["stream_receive_window"] = http2.StreamReceiveWindow
	}
	if http2.ConnectionReceiveWindow != "" {
		target["connection_receive_window"] = http2.ConnectionReceiveWindow
	}
	if http2.MaxConcurrentStreams > 0 {
		target["max_concurrent_streams"] = http2.MaxConcurrentStreams
	}
}
