package protocol

import (
	"fmt"
	"slices"
)

// AllowedRealityUTLSFingerprints lists sing-box uTLS fingerprint values for Reality clients.
var AllowedRealityUTLSFingerprints = []string{
	"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized",
}

// ValidateRealityUTLSFingerprint checks a uTLS fingerprint value.
func ValidateRealityUTLSFingerprint(fp string) error {
	if fp == "" {
		return nil
	}
	if slices.Contains(AllowedRealityUTLSFingerprints, fp) {
		return nil
	}
	return fmt.Errorf("unsupported reality fingerprint %q (allowed: %v)", fp, AllowedRealityUTLSFingerprints)
}

// ResolveRealityUTLSFingerprint returns the fingerprint for share links and client configs.
func ResolveRealityUTLSFingerprint(stored string) string {
	if stored == "" {
		return DefaultRealityShareLinkFingerprint
	}
	return stored
}
