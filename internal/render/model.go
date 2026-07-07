package render

// Config is the top-level sing-box configuration rendered by obscura.
type Config struct {
	Log       LogConfig        `json:"log"`
	Inbounds  []map[string]any `json:"inbounds"`
	Outbounds []Outbound       `json:"outbounds"`
	Route     RouteConfig      `json:"route"`
	Endpoints []map[string]any `json:"endpoints,omitempty"`
}

// LogConfig holds sing-box log settings.
type LogConfig struct {
	Level string `json:"level"`
}

// Outbound holds a minimal sing-box outbound definition.
type Outbound struct {
	Type string `json:"type"`
	Tag  string `json:"tag"`
}

// RouteConfig holds sing-box route settings.
type RouteConfig struct {
	Final string           `json:"final"`
	Rules []map[string]any `json:"rules,omitempty"`
}
