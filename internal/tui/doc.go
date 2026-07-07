// Package tui implements the interactive terminal UI for Obscura using Bubble Tea.
// The UI is structured around a menu/wizard model: the menu lists available actions
// and the wizard guides the user through multi-step flows (create VPN, add client, etc.).
// Bootstrap progress, async command results, and SSH port changes are surfaced
// through message-passing in the Elm-architecture update loop.
package tui
