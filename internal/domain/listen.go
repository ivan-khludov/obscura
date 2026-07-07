package domain

// ListenOptions mirrors sing-box shared listen fields for inbound configuration.
type ListenOptions struct {
	Listen               string `json:"listen"`
	ListenPort           int    `json:"listen_port"`
	BindInterface        string `json:"bind_interface,omitempty"`
	RoutingMark          string `json:"routing_mark,omitempty"`
	ReuseAddr            bool   `json:"reuse_addr,omitempty"`
	Netns                string `json:"netns,omitempty"`
	TCPFastOpen          bool   `json:"tcp_fast_open,omitempty"`
	TCPMultiPath         bool   `json:"tcp_multi_path,omitempty"`
	DisableTCPKeepAlive  bool   `json:"disable_tcp_keep_alive,omitempty"`
	TCPKeepAlive         string `json:"tcp_keep_alive,omitempty"`
	TCPKeepAliveInterval string `json:"tcp_keep_alive_interval,omitempty"`
	UDPFragment          bool   `json:"udp_fragment,omitempty"`
	UDPTimeout           string `json:"udp_timeout,omitempty"`
	Detour               string `json:"detour,omitempty"`
}

// DefaultListenOptions returns listen defaults for a new VPN inbound.
func DefaultListenOptions() ListenOptions {
	return ListenOptions{
		Listen:     "0.0.0.0",
		ListenPort: 1080,
	}
}
