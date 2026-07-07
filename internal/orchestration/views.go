package orchestration

import (
	"time"

	"github.com/ivan-khludov/obscura/internal/domain"
)

// VPNView is an orchestration-owned representation of VPN state.
type VPNView struct {
	ID           int64
	Name         string
	Protocol     string
	Tag          string
	Enabled      bool
	ClientHost   string
	Listen       domain.ListenOptions
	ProtocolData []byte
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// ClientView is an orchestration-owned representation of client state.
type ClientView struct {
	ID        int64
	VPNID     int64
	Name      string
	Username  string
	Password  string
	Enabled   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}
