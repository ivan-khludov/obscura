// Package store provides SQLite-backed persistence for Obscura state.
// It stores VPN instances, their clients, and configuration snapshots (revisions).
// All writes use transactions; the schema is initialised automatically on first open.
package store
