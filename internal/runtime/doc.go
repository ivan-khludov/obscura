// Package runtime wires Obscura application dependencies and manages the sing-box process.
// It assembles the protocol registry, store, manifest, certs, and service layer,
// then exposes a Runtime value used by both CLI commands and the TUI entrypoint.
package runtime
