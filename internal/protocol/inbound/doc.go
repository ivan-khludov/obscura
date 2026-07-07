// Package inbound provides shared rendering helpers for TLS-based protocol adapters.
// It assembles sing-box inbound configuration fragments for TLS (including Reality
// and ACME), transport layers (WebSocket, gRPC, HTTP, HTTPUpgrade, QUIC),
// multiplex, and port fallback. The trojan, vmess, vless, hysteria2, and tuic
// adapters all delegate inbound building to this package.
package inbound
