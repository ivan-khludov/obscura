package vless

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ivan-khludov/obscura/internal/protocol/inbound"
)

// DefaultALPN is the default TLS ALPN list for new VLESS VPNs.
var DefaultALPN = []string{"h2", "http/1.1"}

var parseProtocolDataHook func([]byte) (ProtocolData, error)

// DefaultRealityHandshakePort is the default Reality handshake server port.
const DefaultRealityHandshakePort = 443

// FlowVision is the XTLS vision flow value for direct TLS connections.
const FlowVision = "xtls-rprx-vision"

// TransportModes lists VLESS transport tuning options for the TUI picker.
var TransportModes = []string{
	"Direct",
	"Multiplex",
	"Multiplex (padding)",
	"WebSocket",
	"gRPC",
	"HTTP",
	"HTTPUpgrade",
	"QUIC",
}

// FlowModes lists VLESS flow options for the TUI picker.
var FlowModes = []string{
	"None",
	"XTLS Vision",
}

// TransportHTTP holds HTTP transport options.
type TransportHTTP = inbound.TransportHTTP

// TransportWS holds WebSocket transport options.
type TransportWS = inbound.TransportWS

// TransportGRPC holds gRPC transport options.
type TransportGRPC = inbound.TransportGRPC

// TransportHTTPUpgrade holds HTTPUpgrade transport options.
type TransportHTTPUpgrade = inbound.TransportHTTPUpgrade

// ACMEOptions holds inline ACME configuration for sing-box TLS inbound.
type ACMEOptions = inbound.ACMEOptions

// FallbackTarget is a sing-box fallback server endpoint.
type FallbackTarget = inbound.FallbackTarget

// ProtocolData is the VLESS-specific stored configuration blob.
type ProtocolData struct {
	DefaultFlow                      string                    `json:"default_flow,omitempty"`
	CertPath                         string                    `json:"cert_path,omitempty"`
	KeyPath                          string                    `json:"key_path,omitempty"`
	ServerName                       string                    `json:"server_name,omitempty"`
	ALPN                             []string                  `json:"alpn,omitempty"`
	MinVersion                       string                    `json:"min_version,omitempty"`
	MaxVersion                       string                    `json:"max_version,omitempty"`
	CipherSuites                     []string                  `json:"cipher_suites,omitempty"`
	CurvePreferences                 []string                  `json:"curve_preferences,omitempty"`
	ClientAuthentication             string                    `json:"client_authentication,omitempty"`
	ClientCertificatePaths           []string                  `json:"client_certificate_path,omitempty"`
	ClientCertificatePublicKeySHA256 []string                  `json:"client_certificate_public_key_sha256,omitempty"`
	KernelTX                         bool                      `json:"kernel_tx,omitempty"`
	KernelRX                         bool                      `json:"kernel_rx,omitempty"`
	HandshakeTimeout                 string                    `json:"handshake_timeout,omitempty"`
	ACME                             *ACMEOptions              `json:"acme,omitempty"`
	ECHEnabled                       bool                      `json:"ech_enabled,omitempty"`
	ECHKeyPath                       string                    `json:"ech_key_path,omitempty"`
	RealityEnabled                   bool                      `json:"reality_enabled,omitempty"`
	RealityPrivateKey                string                    `json:"reality_private_key,omitempty"`
	RealityPublicKey                 string                    `json:"reality_public_key,omitempty"`
	RealityShortIDs                  []string                  `json:"reality_short_id,omitempty"`
	RealityHandshakeServer           string                    `json:"reality_handshake_server,omitempty"`
	RealityHandshakePort             int                       `json:"reality_handshake_port,omitempty"`
	RealityMaxTimeDifference         string                    `json:"reality_max_time_difference,omitempty"`
	RealityUTLSFingerprint           string                    `json:"reality_utls_fingerprint,omitempty"`
	FallbackServer                   string                    `json:"fallback_server,omitempty"`
	FallbackPort                     int                       `json:"fallback_port,omitempty"`
	FallbackForALPN                  map[string]FallbackTarget `json:"fallback_for_alpn,omitempty"`
	Multiplex                        bool                      `json:"multiplex,omitempty"`
	MultiplexPadding                 bool                      `json:"multiplex_padding,omitempty"`
	MultiplexBrutal                  bool                      `json:"multiplex_brutal,omitempty"`
	MultiplexBrutalUpMbps            int                       `json:"multiplex_brutal_up_mbps,omitempty"`
	MultiplexBrutalDownMbps          int                       `json:"multiplex_brutal_down_mbps,omitempty"`
	TransportType                    string                    `json:"transport_type,omitempty"`
	TransportHTTP                    *TransportHTTP            `json:"transport_http,omitempty"`
	TransportWS                      *TransportWS              `json:"transport_ws,omitempty"`
	TransportGRPC                    *TransportGRPC            `json:"transport_grpc,omitempty"`
	TransportHTTPUpgrade             *TransportHTTPUpgrade     `json:"transport_httpupgrade,omitempty"`
}

// ParseProtocolData decodes VLESS protocol settings from stored JSON.
func ParseProtocolData(raw []byte) (ProtocolData, error) {
	if parseProtocolDataHook != nil {
		return parseProtocolDataHook(raw)
	}
	if len(raw) == 0 {
		return ProtocolData{}, nil
	}
	var data ProtocolData
	if err := json.Unmarshal(raw, &data); err != nil {
		return ProtocolData{}, fmt.Errorf("parse vless protocol data: %w", err)
	}
	return data, nil
}

// MarshalProtocolData encodes VLESS protocol-specific settings.
func MarshalProtocolData(data ProtocolData) ([]byte, error) {
	return json.Marshal(data)
}

// TLSMode reports which TLS credential mode is active.
func TLSMode(data ProtocolData) string {
	switch {
	case data.RealityEnabled:
		return "reality"
	case data.ACME != nil && len(data.ACME.Domains) > 0:
		return "acme"
	default:
		return "standard"
	}
}

// ValidateOptions checks VLESS protocol data consistency.
func ValidateOptions(data ProtocolData) error {
	if err := inbound.ValidateCredentialModes(data.RealityEnabled, data.ACME != nil && len(data.ACME.Domains) > 0, data.CertPath != "" || data.KeyPath != ""); err != nil {
		return err
	}
	if err := inbound.ValidateReality(data.RealityEnabled, inbound.RealityParams{
		PrivateKey:      data.RealityPrivateKey,
		ShortIDs:        data.RealityShortIDs,
		HandshakeServer: data.RealityHandshakeServer,
		UTLSFingerprint: data.RealityUTLSFingerprint,
	}); err != nil {
		return err
	}
	if err := inbound.ValidateACMEEmail(data.ACME); err != nil {
		return err
	}
	if err := inbound.ValidateECH(data.ECHEnabled, data.ECHKeyPath); err != nil {
		return err
	}
	if err := inbound.ValidateCertKeyPair(data.CertPath, data.KeyPath); err != nil {
		return err
	}
	mode := TLSMode(data)
	if mode == "standard" && data.CertPath == "" && data.KeyPath == "" {
		return errors.New("tls certificate is required for vless (cert_path/key_path, acme, or reality)")
	}
	if data.FallbackPort != 0 || data.FallbackServer != "" || len(data.FallbackForALPN) > 0 {
		return errors.New("tls fallback is only supported for trojan inbounds")
	}
	if data.MultiplexBrutal && (data.MultiplexBrutalUpMbps <= 0 || data.MultiplexBrutalDownMbps <= 0) {
		return errors.New("multiplex brutal requires positive up_mbps and down_mbps")
	}
	if err := validateFlow(data); err != nil {
		return err
	}
	return inbound.ValidateTransport(data.TransportType, data.TransportHTTP, data.TransportWS, data.TransportGRPC, data.TransportHTTPUpgrade)
}

// validateFlow validates protocol options or configuration consistency.
func validateFlow(data ProtocolData) error {
	if data.DefaultFlow != "" && data.DefaultFlow != FlowVision {
		return fmt.Errorf("unsupported default flow %q", data.DefaultFlow)
	}
	if data.DefaultFlow == FlowVision && data.TransportType != "" {
		return errors.New("xtls-rprx-vision flow requires direct transport (no ws/grpc/http transport)")
	}
	return nil
}

// ValidateFlowTransport checks flow/transport compatibility using wizard transport values.
func ValidateFlowTransport(defaultFlow, transport string) error {
	return validateFlow(ProtocolData{
		DefaultFlow:   defaultFlow,
		TransportType: wizardTransportType(transport),
	})
}

// wizardTransportType manages wizard state, validation, or navigation.
func wizardTransportType(transport string) string {
	switch transport {
	case "", "tcp":
		return ""
	default:
		return transport
	}
}

// ValidateClientFlow checks a per-client flow override.
func ValidateClientFlow(flow string) error {
	if flow != "" && flow != FlowVision {
		return fmt.Errorf("unsupported flow %q", flow)
	}
	return nil
}
