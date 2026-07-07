package protocol

// DefaultRealityShareLinkFingerprint is the uTLS fingerprint in Reality share links (vless fp=).
const DefaultRealityShareLinkFingerprint = "chrome"

// ShareLinkInsecureTLS reports whether a share link should skip TLS verification.
// Standard mode uses auto-generated self-signed certificates from obscura.
func ShareLinkInsecureTLS(tlsMode string) bool {
	return tlsMode == "standard"
}
