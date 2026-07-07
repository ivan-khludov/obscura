package inbound

// ACMEOptions holds inline ACME configuration for sing-box TLS inbounds.
type ACMEOptions struct {
	Domains                 []string `json:"domain,omitempty"`
	DataDirectory           string   `json:"data_directory,omitempty"`
	DefaultServerName       string   `json:"default_server_name,omitempty"`
	Email                   string   `json:"email,omitempty"`
	Provider                string   `json:"provider,omitempty"`
	DisableHTTPChallenge    bool     `json:"disable_http_challenge,omitempty"`
	DisableTLSALPNChallenge bool     `json:"disable_tls_alpn_challenge,omitempty"`
	AlternativeHTTPPort     int      `json:"alternative_http_port,omitempty"`
	AlternativeTLSPort      int      `json:"alternative_tls_port,omitempty"`
}

// RenderACME builds the sing-box "acme" TLS fragment.
func RenderACME(acme ACMEOptions) map[string]any {
	out := map[string]any{"domain": acme.Domains}
	if acme.DataDirectory != "" {
		out["data_directory"] = acme.DataDirectory
	}
	if acme.DefaultServerName != "" {
		out["default_server_name"] = acme.DefaultServerName
	}
	if acme.Email != "" {
		out["email"] = acme.Email
	}
	if acme.Provider != "" {
		out["provider"] = acme.Provider
	}
	if acme.DisableHTTPChallenge {
		out["disable_http_challenge"] = true
	}
	if acme.DisableTLSALPNChallenge {
		out["disable_tls_alpn_challenge"] = true
	}
	if acme.AlternativeHTTPPort != 0 {
		out["alternative_http_port"] = acme.AlternativeHTTPPort
	}
	if acme.AlternativeTLSPort != 0 {
		out["alternative_tls_port"] = acme.AlternativeTLSPort
	}
	return out
}
