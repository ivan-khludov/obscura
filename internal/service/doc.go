// Package service implements the core Obscura domain operations.
// It manages VPN and client lifecycle (create, edit, delete), bootstrap,
// SSH port configuration, networking, and protocol-specific validation.
// Service depends on the store, render, certs, manifest, and protocol layers
// and is the single source of truth for business rules.
// The orchestration layer wraps service to adapt CLI/TUI requests into service inputs.
package service
