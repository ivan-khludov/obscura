package service

import (
	"context"

	"github.com/ivan-khludov/obscura/internal/domain"
)

// StateStore persists VPN and client records for service use-cases.
type StateStore interface {
	CreateVPN(ctx context.Context, vpn *domain.VPN) error
	UpdateVPN(ctx context.Context, vpn *domain.VPN) error
	DeleteVPN(ctx context.Context, id int64) error
	GetVPNByName(ctx context.Context, name string) (*domain.VPN, error)
	ListVPNs(ctx context.Context) ([]domain.VPN, error)
	ListEnabledVPNs(ctx context.Context) ([]domain.VPN, error)
	CreateClient(ctx context.Context, client *domain.Client) error
	UpdateClient(ctx context.Context, client *domain.Client) error
	DeleteClient(ctx context.Context, id int64) error
	GetClientByName(ctx context.Context, vpnID int64, name string) (*domain.Client, error)
	ListClientsByVPN(ctx context.Context, vpnID int64) ([]domain.Client, error)
	ListEnabledClientsByVPN(ctx context.Context, vpnID int64) ([]domain.Client, error)
}
