package tuic

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ivan-khludov/obscura/internal/protocol/inbound"
)

// DefaultALPN is the default TLS ALPN list for new TUIC VPNs.
var DefaultALPN = []string{"h3"}

// Congestion control algorithms supported by sing-box TUIC inbound.
const (
	CongestionCubic   = "cubic"
	CongestionNewReno = "new_reno"
	CongestionBBR     = "bbr"
)

var congestionControls = map[string]struct{}{
	CongestionCubic:   {},
	CongestionNewReno: {},
	CongestionBBR:     {},
}

// ACMEOptions holds inline ACME configuration for sing-box TLS inbound.
type ACMEOptions = inbound.ACMEOptions

// HTTP2Options holds HTTP2 tuning fields embedded in QUIC inbound options.
type HTTP2Options = inbound.HTTP2Options

// ProtocolData is the TUIC-specific stored configuration blob.
type ProtocolData struct {
	CertPath                         string        `json:"cert_path,omitempty"`
	KeyPath                          string        `json:"key_path,omitempty"`
	ServerName                       string        `json:"server_name,omitempty"`
	ALPN                             []string      `json:"alpn,omitempty"`
	MinVersion                       string        `json:"min_version,omitempty"`
	MaxVersion                       string        `json:"max_version,omitempty"`
	CipherSuites                     []string      `json:"cipher_suites,omitempty"`
	CurvePreferences                 []string      `json:"curve_preferences,omitempty"`
	ClientAuthentication             string        `json:"client_authentication,omitempty"`
	ClientCertificatePaths           []string      `json:"client_certificate_path,omitempty"`
	ClientCertificatePublicKeySHA256 []string      `json:"client_certificate_public_key_sha256,omitempty"`
	KernelTX                         bool          `json:"kernel_tx,omitempty"`
	KernelRX                         bool          `json:"kernel_rx,omitempty"`
	HandshakeTimeout                 string        `json:"handshake_timeout,omitempty"`
	ACME                             *ACMEOptions  `json:"acme,omitempty"`
	ECHEnabled                       bool          `json:"ech_enabled,omitempty"`
	ECHKeyPath                       string        `json:"ech_key_path,omitempty"`
	CongestionControl                string        `json:"congestion_control,omitempty"`
	AuthTimeout                      string        `json:"auth_timeout,omitempty"`
	ZeroRTTHandshake                 bool          `json:"zero_rtt_handshake,omitempty"`
	Heartbeat                        string        `json:"heartbeat,omitempty"`
	InitialPacketSize                int           `json:"initial_packet_size,omitempty"`
	DisablePathMTUDiscovery          bool          `json:"disable_path_mtu_discovery,omitempty"`
	HTTP2                            *HTTP2Options `json:"http2,omitempty"`
}

// ParseProtocolData decodes TUIC protocol settings from stored JSON.
func ParseProtocolData(raw []byte) (ProtocolData, error) {
	if len(raw) == 0 {
		return ProtocolData{}, nil
	}
	var data ProtocolData
	if err := json.Unmarshal(raw, &data); err != nil {
		return ProtocolData{}, fmt.Errorf("parse tuic protocol data: %w", err)
	}
	return data, nil
}

// MarshalProtocolData encodes TUIC protocol-specific settings.
func MarshalProtocolData(data ProtocolData) ([]byte, error) {
	return json.Marshal(data)
}

// TLSMode reports which TLS credential mode is active.
func TLSMode(data ProtocolData) string {
	if data.ACME != nil && len(data.ACME.Domains) > 0 {
		return "acme"
	}
	return "standard"
}

// ValidateOptions checks TUIC protocol data consistency.
func ValidateOptions(data ProtocolData) error {
	if err := inbound.ValidateCredentialModesNoReality(data.ACME != nil && len(data.ACME.Domains) > 0, data.CertPath != "" || data.KeyPath != ""); err != nil {
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
	if TLSMode(data) == "standard" && data.CertPath == "" && data.KeyPath == "" {
		return errors.New("tls certificate is required for tuic (cert_path/key_path or acme)")
	}
	if data.CongestionControl != "" {
		if _, ok := congestionControls[data.CongestionControl]; !ok {
			return fmt.Errorf("unsupported congestion_control %q", data.CongestionControl)
		}
	}
	return nil
}
