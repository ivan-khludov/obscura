package orchestration

import (
	"context"

	"github.com/ivan-khludov/obscura/internal/apply"
	"github.com/ivan-khludov/obscura/internal/doctor"
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/manifest"
	"github.com/ivan-khludov/obscura/internal/service"
)

// Backend is the service surface used by Facade.
type Backend interface {
	CreateVPN(ctx context.Context, in CreateVPNInput) (*service.CreateVPNResult, error)
	ValidateCreateVPNWizardStep(ctx context.Context, in CreateVPNInput, step WizardValidateStep) error
	UpdateVPN(ctx context.Context, name string, in UpdateVPNInput, reapply bool) (*domain.VPN, error)
	UpdateClient(ctx context.Context, in UpdateClientInput, reapply bool) (*domain.Client, error)
	AddClient(ctx context.Context, in service.AddClientInput, reapply bool) (*domain.Client, string, error)
	ClientURI(ctx context.Context, vpnName, clientName string) (string, error)
	ClientQRContent(ctx context.Context, vpnName, clientName string) (string, error)
	RotateClientPassword(ctx context.Context, vpnName, clientName string) (string, string, error)
	ListCongestionControls() ([]string, error)
	CongestionControl() string
	SetCongestionControl(ctx context.Context, algorithm string) error
	UninstallPlan() manifest.UninstallPlan
	UninstallFull(ctx context.Context, wipeData bool) error
	DeleteVPN(ctx context.Context, name string) error
	ListVPNs(ctx context.Context) ([]domain.VPN, error)
	GetVPN(ctx context.Context, name string) (*domain.VPN, error)
	RemoveClient(ctx context.Context, vpnName, clientName string) error
	ListClients(ctx context.Context, vpnName string) ([]domain.Client, error)
	Bootstrap(ctx context.Context, opts service.BootstrapOptions) error
	IsBootstrapped() bool
	Apply(ctx context.Context, dryRun bool) (*apply.Result, error)
	Rollback(ctx context.Context) error
	Status(ctx context.Context) (*service.StatusSummary, error)
	Doctor(ctx context.Context) []doctor.CheckResult
	CreateBackup(ctx context.Context) (string, error)
	ListBackups(ctx context.Context) ([]service.BackupEntry, error)
	RestoreBackup(ctx context.Context, archivePath string) error
	SSHPort() int
	SetSSHPort(ctx context.Context, port int) error
	ListProtocols() []string
	ValidateVPNName(ctx context.Context, name string) error
	ValidateVPNListenPort(ctx context.Context, port int) error
}

var _ Backend = (*service.Service)(nil)
