package inbound

// TransportHTTP holds HTTP transport options.
type TransportHTTP struct {
	Host        []string          `json:"host,omitempty"`
	Path        string            `json:"path,omitempty"`
	Method      string            `json:"method,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	IdleTimeout string            `json:"idle_timeout,omitempty"`
	PingTimeout string            `json:"ping_timeout,omitempty"`
}

// TransportWS holds WebSocket transport options.
type TransportWS struct {
	Path                string            `json:"path,omitempty"`
	Headers             map[string]string `json:"headers,omitempty"`
	MaxEarlyData        int               `json:"max_early_data,omitempty"`
	EarlyDataHeaderName string            `json:"early_data_header_name,omitempty"`
}

// TransportGRPC holds gRPC transport options.
type TransportGRPC struct {
	ServiceName         string `json:"service_name,omitempty"`
	IdleTimeout         string `json:"idle_timeout,omitempty"`
	PingTimeout         string `json:"ping_timeout,omitempty"`
	PermitWithoutStream bool   `json:"permit_without_stream,omitempty"`
}

// TransportHTTPUpgrade holds HTTPUpgrade transport options.
type TransportHTTPUpgrade struct {
	Host    string            `json:"host,omitempty"`
	Path    string            `json:"path,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

// RenderTransport dispatches to the sing-box transport fragment for the given type.
func RenderTransport(transportType string, http *TransportHTTP, ws *TransportWS, grpc *TransportGRPC, httpUpgrade *TransportHTTPUpgrade) map[string]any {
	switch transportType {
	case "", "quic":
		if transportType == "quic" {
			return map[string]any{"type": "quic"}
		}
		return nil
	case "http":
		return RenderTransportHTTP(http)
	case "ws":
		return RenderTransportWS(ws)
	case "grpc":
		return RenderTransportGRPC(grpc)
	case "httpupgrade":
		return RenderTransportHTTPUpgrade(httpUpgrade)
	default:
		return nil
	}
}

// RenderTransportHTTP builds the sing-box HTTP transport fragment.
func RenderTransportHTTP(http *TransportHTTP) map[string]any {
	out := map[string]any{"type": "http"}
	if len(http.Host) > 0 {
		out["host"] = http.Host
	}
	if http.Path != "" {
		out["path"] = http.Path
	}
	if http.Method != "" {
		out["method"] = http.Method
	}
	if len(http.Headers) > 0 {
		out["headers"] = http.Headers
	}
	if http.IdleTimeout != "" {
		out["idle_timeout"] = http.IdleTimeout
	}
	if http.PingTimeout != "" {
		out["ping_timeout"] = http.PingTimeout
	}
	return out
}

// RenderTransportWS builds the sing-box WebSocket transport fragment.
func RenderTransportWS(ws *TransportWS) map[string]any {
	out := map[string]any{"type": "ws"}
	if ws.Path != "" {
		out["path"] = ws.Path
	}
	if len(ws.Headers) > 0 {
		out["headers"] = ws.Headers
	}
	if ws.MaxEarlyData != 0 {
		out["max_early_data"] = ws.MaxEarlyData
	}
	if ws.EarlyDataHeaderName != "" {
		out["early_data_header_name"] = ws.EarlyDataHeaderName
	}
	return out
}

// RenderTransportGRPC builds the sing-box gRPC transport fragment.
func RenderTransportGRPC(grpc *TransportGRPC) map[string]any {
	out := map[string]any{"type": "grpc"}
	if grpc.ServiceName != "" {
		out["service_name"] = grpc.ServiceName
	}
	if grpc.IdleTimeout != "" {
		out["idle_timeout"] = grpc.IdleTimeout
	}
	if grpc.PingTimeout != "" {
		out["ping_timeout"] = grpc.PingTimeout
	}
	if grpc.PermitWithoutStream {
		out["permit_without_stream"] = true
	}
	return out
}

// ALPNForTransport returns the ALPN list required by the given transport type,
// overriding defaultALPN when the transport imposes its own constraint.
// HTTPUpgrade requires HTTP/1.1 because it uses connection hijacking, which is
// incompatible with h2.
func ALPNForTransport(transportType string, defaultALPN []string) []string {
	if transportType == "httpupgrade" {
		return []string{"http/1.1"}
	}
	return defaultALPN
}

// RenderTransportHTTPUpgrade builds the sing-box HTTPUpgrade transport fragment.
func RenderTransportHTTPUpgrade(hu *TransportHTTPUpgrade) map[string]any {
	out := map[string]any{"type": "httpupgrade"}
	if hu.Host != "" {
		out["host"] = hu.Host
	}
	if hu.Path != "" {
		out["path"] = hu.Path
	}
	if len(hu.Headers) > 0 {
		out["headers"] = hu.Headers
	}
	return out
}
