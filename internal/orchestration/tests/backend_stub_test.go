package orchestration_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ivan-khludov/obscura/internal/apply"
	"github.com/ivan-khludov/obscura/internal/doctor"
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/manifest"
	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/service"
)

type delegatingBackend struct {
	base orchestration.Backend

	createVPNFn                   func(ctx context.Context, in orchestration.CreateVPNInput) (*service.CreateVPNResult, error)
	validateCreateVPNWizardStepFn func(ctx context.Context, in orchestration.CreateVPNInput, step orchestration.WizardValidateStep) error
	updateVPNFn                   func(ctx context.Context, name string, in orchestration.UpdateVPNInput, reapply bool) (*domain.VPN, error)
	updateClientFn                func(ctx context.Context, in orchestration.UpdateClientInput, reapply bool) (*domain.Client, error)
	addClientFn                   func(ctx context.Context, in service.AddClientInput, reapply bool) (*domain.Client, string, error)
	clientURIFn                   func(ctx context.Context, vpnName, clientName string) (string, error)
	clientQRContentFn             func(ctx context.Context, vpnName, clientName string) (string, error)
	rotateClientPasswordFn        func(ctx context.Context, vpnName, clientName string) (string, string, error)
	listCongestionControlsFn      func() ([]string, error)
	congestionControlFn           func() string
	setCongestionControlFn        func(ctx context.Context, algorithm string) error
	uninstallFullFn               func(ctx context.Context, wipeData bool) error
	deleteVPNFn                   func(ctx context.Context, name string) error
	listVPNsFn                    func(ctx context.Context) ([]domain.VPN, error)
	getVPNFn                      func(ctx context.Context, name string) (*domain.VPN, error)
	removeClientFn                func(ctx context.Context, vpnName, clientName string) error
	listClientsFn                 func(ctx context.Context, vpnName string) ([]domain.Client, error)
	bootstrapFn                   func(ctx context.Context, opts service.BootstrapOptions) error
	isBootstrappedFn              func() bool
	applyFn                       func(ctx context.Context, dryRun bool) (*apply.Result, error)
	rollbackFn                    func(ctx context.Context) error
	statusFn                      func(ctx context.Context) (*service.StatusSummary, error)
	createBackupFn                func(ctx context.Context) (string, error)
	listBackupsFn                 func(ctx context.Context) ([]service.BackupEntry, error)
	restoreBackupFn               func(ctx context.Context, archivePath string) error
	sshPortFn                     func() int
	setSSHPortFn                  func(ctx context.Context, port int) error
	validateVPNNameFn             func(ctx context.Context, name string) error
	validateVPNListenPortFn       func(ctx context.Context, port int) error
}

func newDelegatingBackend(base orchestration.Backend) *delegatingBackend {
	return &delegatingBackend{base: base}
}

func (d *delegatingBackend) CreateVPN(ctx context.Context, in orchestration.CreateVPNInput) (*service.CreateVPNResult, error) {
	if d.createVPNFn != nil {
		return d.createVPNFn(ctx, in)
	}
	return d.base.CreateVPN(ctx, in)
}

func (d *delegatingBackend) ValidateCreateVPNWizardStep(ctx context.Context, in orchestration.CreateVPNInput, step orchestration.WizardValidateStep) error {
	if d.validateCreateVPNWizardStepFn != nil {
		return d.validateCreateVPNWizardStepFn(ctx, in, step)
	}
	return d.base.ValidateCreateVPNWizardStep(ctx, in, step)
}

func (d *delegatingBackend) UpdateVPN(ctx context.Context, name string, in orchestration.UpdateVPNInput, reapply bool) (*domain.VPN, error) {
	if d.updateVPNFn != nil {
		return d.updateVPNFn(ctx, name, in, reapply)
	}
	return d.base.UpdateVPN(ctx, name, in, reapply)
}

func (d *delegatingBackend) UpdateClient(ctx context.Context, in orchestration.UpdateClientInput, reapply bool) (*domain.Client, error) {
	if d.updateClientFn != nil {
		return d.updateClientFn(ctx, in, reapply)
	}
	return d.base.UpdateClient(ctx, in, reapply)
}

func (d *delegatingBackend) AddClient(ctx context.Context, in service.AddClientInput, reapply bool) (*domain.Client, string, error) {
	if d.addClientFn != nil {
		return d.addClientFn(ctx, in, reapply)
	}
	return d.base.AddClient(ctx, in, reapply)
}

func (d *delegatingBackend) ClientURI(ctx context.Context, vpnName, clientName string) (string, error) {
	if d.clientURIFn != nil {
		return d.clientURIFn(ctx, vpnName, clientName)
	}
	return d.base.ClientURI(ctx, vpnName, clientName)
}

func (d *delegatingBackend) ClientQRContent(ctx context.Context, vpnName, clientName string) (string, error) {
	if d.clientQRContentFn != nil {
		return d.clientQRContentFn(ctx, vpnName, clientName)
	}
	return d.base.ClientQRContent(ctx, vpnName, clientName)
}

func (d *delegatingBackend) RotateClientPassword(ctx context.Context, vpnName, clientName string) (string, string, error) {
	if d.rotateClientPasswordFn != nil {
		return d.rotateClientPasswordFn(ctx, vpnName, clientName)
	}
	return d.base.RotateClientPassword(ctx, vpnName, clientName)
}

func (d *delegatingBackend) ListCongestionControls() ([]string, error) {
	if d.listCongestionControlsFn != nil {
		return d.listCongestionControlsFn()
	}
	return d.base.ListCongestionControls()
}

func (d *delegatingBackend) CongestionControl() string {
	if d.congestionControlFn != nil {
		return d.congestionControlFn()
	}
	return d.base.CongestionControl()
}

func (d *delegatingBackend) SetCongestionControl(ctx context.Context, algorithm string) error {
	if d.setCongestionControlFn != nil {
		return d.setCongestionControlFn(ctx, algorithm)
	}
	return d.base.SetCongestionControl(ctx, algorithm)
}

func (d *delegatingBackend) UninstallPlan() manifest.UninstallPlan {
	return d.base.UninstallPlan()
}

func (d *delegatingBackend) UninstallFull(ctx context.Context, wipeData bool) error {
	if d.uninstallFullFn != nil {
		return d.uninstallFullFn(ctx, wipeData)
	}
	return d.base.UninstallFull(ctx, wipeData)
}

func (d *delegatingBackend) DeleteVPN(ctx context.Context, name string) error {
	if d.deleteVPNFn != nil {
		return d.deleteVPNFn(ctx, name)
	}
	return d.base.DeleteVPN(ctx, name)
}

func (d *delegatingBackend) ListVPNs(ctx context.Context) ([]domain.VPN, error) {
	if d.listVPNsFn != nil {
		return d.listVPNsFn(ctx)
	}
	return d.base.ListVPNs(ctx)
}

func (d *delegatingBackend) GetVPN(ctx context.Context, name string) (*domain.VPN, error) {
	if d.getVPNFn != nil {
		return d.getVPNFn(ctx, name)
	}
	return d.base.GetVPN(ctx, name)
}

func (d *delegatingBackend) RemoveClient(ctx context.Context, vpnName, clientName string) error {
	if d.removeClientFn != nil {
		return d.removeClientFn(ctx, vpnName, clientName)
	}
	return d.base.RemoveClient(ctx, vpnName, clientName)
}

func (d *delegatingBackend) ListClients(ctx context.Context, vpnName string) ([]domain.Client, error) {
	if d.listClientsFn != nil {
		return d.listClientsFn(ctx, vpnName)
	}
	return d.base.ListClients(ctx, vpnName)
}

func (d *delegatingBackend) Bootstrap(ctx context.Context, opts service.BootstrapOptions) error {
	if d.bootstrapFn != nil {
		return d.bootstrapFn(ctx, opts)
	}
	return d.base.Bootstrap(ctx, opts)
}

func (d *delegatingBackend) IsBootstrapped() bool {
	if d.isBootstrappedFn != nil {
		return d.isBootstrappedFn()
	}
	return d.base.IsBootstrapped()
}

func (d *delegatingBackend) Apply(ctx context.Context, dryRun bool) (*apply.Result, error) {
	if d.applyFn != nil {
		return d.applyFn(ctx, dryRun)
	}
	return d.base.Apply(ctx, dryRun)
}

func (d *delegatingBackend) Rollback(ctx context.Context) error {
	if d.rollbackFn != nil {
		return d.rollbackFn(ctx)
	}
	return d.base.Rollback(ctx)
}

func (d *delegatingBackend) Status(ctx context.Context) (*service.StatusSummary, error) {
	if d.statusFn != nil {
		return d.statusFn(ctx)
	}
	return d.base.Status(ctx)
}

func (d *delegatingBackend) Doctor(ctx context.Context) []doctor.CheckResult {
	return d.base.Doctor(ctx)
}

func (d *delegatingBackend) CreateBackup(ctx context.Context) (string, error) {
	if d.createBackupFn != nil {
		return d.createBackupFn(ctx)
	}
	return d.base.CreateBackup(ctx)
}

func (d *delegatingBackend) ListBackups(ctx context.Context) ([]service.BackupEntry, error) {
	if d.listBackupsFn != nil {
		return d.listBackupsFn(ctx)
	}
	return d.base.ListBackups(ctx)
}

func (d *delegatingBackend) RestoreBackup(ctx context.Context, archivePath string) error {
	if d.restoreBackupFn != nil {
		return d.restoreBackupFn(ctx, archivePath)
	}
	return d.base.RestoreBackup(ctx, archivePath)
}

func (d *delegatingBackend) SSHPort() int {
	if d.sshPortFn != nil {
		return d.sshPortFn()
	}
	return d.base.SSHPort()
}

func (d *delegatingBackend) SetSSHPort(ctx context.Context, port int) error {
	if d.setSSHPortFn != nil {
		return d.setSSHPortFn(ctx, port)
	}
	return d.base.SetSSHPort(ctx, port)
}

func (d *delegatingBackend) ListProtocols() []string {
	return d.base.ListProtocols()
}

func (d *delegatingBackend) ValidateVPNName(ctx context.Context, name string) error {
	if d.validateVPNNameFn != nil {
		return d.validateVPNNameFn(ctx, name)
	}
	return d.base.ValidateVPNName(ctx, name)
}

func (d *delegatingBackend) ValidateVPNListenPort(ctx context.Context, port int) error {
	if d.validateVPNListenPortFn != nil {
		return d.validateVPNListenPortFn(ctx, port)
	}
	return d.base.ValidateVPNListenPort(ctx, port)
}

var errStub = errors.New("stub error")

func stubFacade(t *testing.T) (*orchestration.Facade, *delegatingBackend) {
	t.Helper()
	base := newTestFacadeWithBackend(t)
	stub := newDelegatingBackend(base)
	return orchestration.NewWithBackend(stub), stub
}
