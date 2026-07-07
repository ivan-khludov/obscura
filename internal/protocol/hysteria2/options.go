package hysteria2

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/ivan-khludov/obscura/internal/protocol/inbound"
)

// DefaultALPN is the default TLS ALPN list for new Hysteria2 VPNs.
var DefaultALPN = []string{"h3"}

// Masquerade types for typed masquerade configuration.
const (
	MasqueradeTypeFile   = "file"
	MasqueradeTypeProxy  = "proxy"
	MasqueradeTypeString = "string"
)

// BBR profile values (sing-box 1.14+).
const (
	BBRProfileConservative = "conservative"
	BBRProfileStandard     = "standard"
	BBRProfileAggressive   = "aggressive"
)

var bbrProfiles = map[string]struct{}{
	BBRProfileConservative: {},
	BBRProfileStandard:     {},
	BBRProfileAggressive:   {},
}

var realmIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

// ACMEOptions holds inline ACME configuration for sing-box TLS inbound.
type ACMEOptions = inbound.ACMEOptions

// MasqueradeObject holds typed masquerade configuration.
type MasqueradeObject struct {
	Type        string            `json:"type,omitempty"`
	Directory   string            `json:"directory,omitempty"`
	URL         string            `json:"url,omitempty"`
	RewriteHost bool              `json:"rewrite_host,omitempty"`
	StatusCode  int               `json:"status_code,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Content     string            `json:"content,omitempty"`
}

// RealmOptions holds Hysteria Realm NAT traversal configuration.
type RealmOptions struct {
	ServerURL          string          `json:"server_url,omitempty"`
	Token              string          `json:"token,omitempty"`
	RealmID            string          `json:"realm_id,omitempty"`
	STUNServers        []string        `json:"stun_servers,omitempty"`
	STUNDomainResolver json.RawMessage `json:"stun_domain_resolver,omitempty"`
	HTTPClient         json.RawMessage `json:"http_client,omitempty"`
}

// HTTP2Options holds HTTP2 tuning fields embedded in QUIC inbound options.
type HTTP2Options = inbound.HTTP2Options

// ProtocolData is the Hysteria2-specific stored configuration blob.
type ProtocolData struct {
	CertPath                         string            `json:"cert_path,omitempty"`
	KeyPath                          string            `json:"key_path,omitempty"`
	ServerName                       string            `json:"server_name,omitempty"`
	ALPN                             []string          `json:"alpn,omitempty"`
	MinVersion                       string            `json:"min_version,omitempty"`
	MaxVersion                       string            `json:"max_version,omitempty"`
	CipherSuites                     []string          `json:"cipher_suites,omitempty"`
	CurvePreferences                 []string          `json:"curve_preferences,omitempty"`
	ClientAuthentication             string            `json:"client_authentication,omitempty"`
	ClientCertificatePaths           []string          `json:"client_certificate_path,omitempty"`
	ClientCertificatePublicKeySHA256 []string          `json:"client_certificate_public_key_sha256,omitempty"`
	KernelTX                         bool              `json:"kernel_tx,omitempty"`
	KernelRX                         bool              `json:"kernel_rx,omitempty"`
	HandshakeTimeout                 string            `json:"handshake_timeout,omitempty"`
	ACME                             *ACMEOptions      `json:"acme,omitempty"`
	ECHEnabled                       bool              `json:"ech_enabled,omitempty"`
	ECHKeyPath                       string            `json:"ech_key_path,omitempty"`
	UpMbps                           int               `json:"up_mbps,omitempty"`
	DownMbps                         int               `json:"down_mbps,omitempty"`
	IgnoreClientBandwidth            bool              `json:"ignore_client_bandwidth,omitempty"`
	ObfsPassword                     string            `json:"obfs_password,omitempty"`
	MasqueradeURL                    string            `json:"masquerade_url,omitempty"`
	Masquerade                       *MasqueradeObject `json:"masquerade,omitempty"`
	BrutalDebug                      bool              `json:"brutal_debug,omitempty"`
	BBRProfile                       string            `json:"bbr_profile,omitempty"`
	InitialPacketSize                int               `json:"initial_packet_size,omitempty"`
	DisablePathMTUDiscovery          bool              `json:"disable_path_mtu_discovery,omitempty"`
	HTTP2                            *HTTP2Options     `json:"http2,omitempty"`
	Realm                            *RealmOptions     `json:"realm,omitempty"`
}

// ParseProtocolData decodes Hysteria2 protocol settings from stored JSON.
func ParseProtocolData(raw []byte) (ProtocolData, error) {
	if len(raw) == 0 {
		return ProtocolData{}, nil
	}
	var data ProtocolData
	if err := json.Unmarshal(raw, &data); err != nil {
		return ProtocolData{}, fmt.Errorf("parse hysteria2 protocol data: %w", err)
	}
	return data, nil
}

// MarshalProtocolData encodes Hysteria2 protocol-specific settings.
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

// ValidateOptions checks Hysteria2 protocol data consistency.
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
		return errors.New("tls certificate is required for hysteria2 (cert_path/key_path or acme)")
	}
	if data.UpMbps > 0 || data.DownMbps > 0 {
		if data.IgnoreClientBandwidth {
			return errors.New("ignore_client_bandwidth conflicts with up_mbps/down_mbps")
		}
	}
	if data.MasqueradeURL != "" && data.Masquerade != nil {
		return errors.New("masquerade URL string and masquerade object are mutually exclusive")
	}
	if data.Masquerade != nil {
		if err := validateMasqueradeObject(*data.Masquerade); err != nil {
			return err
		}
	}
	if data.BBRProfile != "" {
		if _, ok := bbrProfiles[data.BBRProfile]; !ok {
			return fmt.Errorf("unsupported bbr_profile %q", data.BBRProfile)
		}
	}
	if data.Realm != nil {
		if err := validateRealm(*data.Realm); err != nil {
			return err
		}
	}
	return nil
}

// validateMasqueradeObject validates protocol options or configuration consistency.
func validateMasqueradeObject(m MasqueradeObject) error {
	switch m.Type {
	case MasqueradeTypeFile:
		if m.Directory == "" {
			return errors.New("masquerade.directory is required for file masquerade")
		}
	case MasqueradeTypeProxy:
		if m.URL == "" {
			return errors.New("masquerade.url is required for proxy masquerade")
		}
	case MasqueradeTypeString:
		if m.StatusCode == 0 {
			return errors.New("masquerade.status_code is required for string masquerade")
		}
	case "":
		return errors.New("masquerade.type is required when masquerade object is set")
	default:
		return fmt.Errorf("unsupported masquerade type %q", m.Type)
	}
	return nil
}

// validateRealm validates protocol options or configuration consistency.
func validateRealm(r RealmOptions) error {
	if r.ServerURL == "" {
		return errors.New("realm.server_url is required when realm is configured")
	}
	if r.RealmID == "" {
		return errors.New("realm.realm_id is required when realm is configured")
	}
	if !realmIDPattern.MatchString(r.RealmID) {
		return errors.New("realm.realm_id must match ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
	}
	if len(r.STUNServers) == 0 {
		return errors.New("realm.stun_servers is required when realm is configured")
	}
	return nil
}
