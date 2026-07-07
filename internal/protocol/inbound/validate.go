package inbound

import (
	"errors"
	"fmt"
)

// ValidateCredentialModes rejects configuring more than one TLS credential
// mode at once. Use for protocols that support Reality (trojan, vmess, vless).
func ValidateCredentialModes(realitySet, acmeSet, certSet bool) error {
	modes := 0
	if realitySet {
		modes++
	}
	if acmeSet {
		modes++
	}
	if certSet {
		modes++
	}
	if modes > 1 {
		return errors.New("only one TLS credential mode is allowed: standard cert, acme, or reality")
	}
	return nil
}

// ValidateCredentialModesNoReality rejects configuring more than one TLS
// credential mode at once, for protocols without Reality support (hysteria2, tuic).
func ValidateCredentialModesNoReality(acmeSet, certSet bool) error {
	if acmeSet && certSet {
		return errors.New("only one TLS credential mode is allowed: standard cert or acme")
	}
	return nil
}

// ValidateACMEEmail requires an email address whenever ACME domains are configured.
func ValidateACMEEmail(acme *ACMEOptions) error {
	if acme != nil && len(acme.Domains) > 0 && acme.Email == "" {
		return errors.New("acme email is required when acme domain is set")
	}
	return nil
}

// ValidateECH requires a key path whenever ECH is enabled.
func ValidateECH(enabled bool, keyPath string) error {
	if enabled && keyPath == "" {
		return errors.New("ech_key_path is required when ech is enabled")
	}
	return nil
}

// ValidateCertKeyPair requires cert_path and key_path to be both set or both empty.
func ValidateCertKeyPair(certPath, keyPath string) error {
	if (certPath == "") != (keyPath == "") {
		return errors.New("cert_path and key_path must both be set or both empty")
	}
	return nil
}

// ValidateTransport checks that the settings object matching transportType is present.
func ValidateTransport(transportType string, http *TransportHTTP, ws *TransportWS, grpc *TransportGRPC, httpUpgrade *TransportHTTPUpgrade) error {
	switch transportType {
	case "", "quic":
		return nil
	case "http":
		if http == nil {
			return errors.New("transport_http settings are required for http transport")
		}
	case "ws":
		if ws == nil {
			return errors.New("transport_ws settings are required for ws transport")
		}
	case "grpc":
		if grpc == nil {
			return errors.New("transport_grpc settings are required for grpc transport")
		}
	case "httpupgrade":
		if httpUpgrade == nil {
			return errors.New("transport_httpupgrade settings are required for httpupgrade transport")
		}
	default:
		return fmt.Errorf("unsupported transport type %q", transportType)
	}
	return nil
}
