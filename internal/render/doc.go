// Package render builds sing-box JSON configuration from Obscura domain state.
// It iterates enabled VPNs, delegates inbound/endpoint rendering to protocol adapters,
// and produces a complete config object that apply writes to disk and reloads in sing-box.
package render
