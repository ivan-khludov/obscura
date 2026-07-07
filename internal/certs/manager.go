// Package certs provides certificate management stubs for future TLS-based protocols.
package certs

import "errors"

// ErrNotSupported is returned when certificate operations are unavailable for the current protocol.
var ErrNotSupported = errors.New("certificates are not used for SOCKS5; available in future protocol versions")

// Manager defines certificate lifecycle operations for future use.
type Manager interface {
	Issue(domain, email string) error
	Renew() error
	Remove(domain string) error
}

// NopManager is a stub certificate manager for SOCKS5-only deployments.
type NopManager struct{}

// Issue returns ErrNotSupported.
func (NopManager) Issue(_, _ string) error { return ErrNotSupported }

// Renew returns ErrNotSupported.
func (NopManager) Renew() error { return ErrNotSupported }

// Remove returns ErrNotSupported.
func (NopManager) Remove(_ string) error { return ErrNotSupported }
