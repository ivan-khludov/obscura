package domain

import "time"

// Client represents an authenticated user of a VPN inbound.
type Client struct {
	ID        int64
	VPNID     int64
	Name      string
	Username  string
	Password  string
	Enabled   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ClientConfig is the input shape used by protocol adapters during validation and rendering.
type ClientConfig struct {
	Name     string
	Username string
	Password string
	Enabled  bool
}
