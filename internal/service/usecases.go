package service

import (
	"context"

	"github.com/ivan-khludov/obscura/internal/apply"
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/manifest"
)

// VPNService groups VPN lifecycle use cases behind the Service facade.
type VPNService struct {
	root *Service
}

// ClientService groups client lifecycle use cases behind the Service facade.
type ClientService struct {
	root *Service
}

// SystemService groups apply, rollback, status, doctor, SSH, and network use cases.
type SystemService struct {
	root *Service
}

// BootstrapService groups bootstrap and installation use cases.
type BootstrapService struct {
	root *Service
}

// MaintenanceService groups backup, restore, and uninstall use cases.
type MaintenanceService struct {
	root *Service
}

func newUseCases(root *Service) (*VPNService, *ClientService, *SystemService, *BootstrapService, *MaintenanceService) {
	return &VPNService{
			root: root,
		},
		&ClientService{
			root: root,
		},
		&SystemService{
			root: root,
		},
		&BootstrapService{
			root: root,
		},
		&MaintenanceService{
			root: root,
		}
}

// Create runs VPN creation use cases.
func (s *VPNService) Create(ctx context.Context, in CreateVPNInput) (*CreateVPNResult, error) {
	return s.root.createVPN(ctx, in)
}

// Update runs VPN update use cases.
func (s *VPNService) Update(ctx context.Context, name string, in UpdateVPNInput, reapply bool) (*domain.VPN, error) {
	return s.root.updateVPN(ctx, name, in, reapply)
}

// Delete runs VPN deletion use cases.
func (s *VPNService) Delete(ctx context.Context, name string) error {
	return s.root.deleteVPN(ctx, name)
}

// List returns VPN records.
func (s *VPNService) List(ctx context.Context) ([]domain.VPN, error) {
	return s.root.listVPNs(ctx)
}

// Get returns one VPN record.
func (s *VPNService) Get(ctx context.Context, name string) (*domain.VPN, error) {
	return s.root.getVPN(ctx, name)
}

// CreateVPN delegates to VPNService for backward compatibility.
func (s *Service) CreateVPN(ctx context.Context, in CreateVPNInput) (*CreateVPNResult, error) {
	return s.VPNs.Create(ctx, in)
}

// UpdateVPN delegates to VPNService for backward compatibility.
func (s *Service) UpdateVPN(ctx context.Context, name string, in UpdateVPNInput, reapply bool) (*domain.VPN, error) {
	return s.VPNs.Update(ctx, name, in, reapply)
}

// DeleteVPN delegates to VPNService for backward compatibility.
func (s *Service) DeleteVPN(ctx context.Context, name string) error {
	return s.VPNs.Delete(ctx, name)
}

// ListVPNs delegates to VPNService for backward compatibility.
func (s *Service) ListVPNs(ctx context.Context) ([]domain.VPN, error) {
	return s.VPNs.List(ctx)
}

// GetVPN delegates to VPNService for backward compatibility.
func (s *Service) GetVPN(ctx context.Context, name string) (*domain.VPN, error) {
	return s.VPNs.Get(ctx, name)
}

// Add runs client creation use cases.
func (s *ClientService) Add(ctx context.Context, in AddClientInput, reapply bool) (*domain.Client, string, error) {
	return s.root.addClient(ctx, in, reapply)
}

// Update runs client update use cases.
func (s *ClientService) Update(ctx context.Context, in UpdateClientInput, reapply bool) (*domain.Client, error) {
	return s.root.updateClient(ctx, in, reapply)
}

// Remove runs client deletion use cases.
func (s *ClientService) Remove(ctx context.Context, vpnName, clientName string) error {
	return s.root.removeClient(ctx, vpnName, clientName)
}

// List returns clients for a VPN.
func (s *ClientService) List(ctx context.Context, vpnName string) ([]domain.Client, error) {
	return s.root.listClients(ctx, vpnName)
}

// URI returns the share URI for a client.
func (s *ClientService) URI(ctx context.Context, vpnName, clientName string) (string, error) {
	return s.root.clientURI(ctx, vpnName, clientName)
}

// QRContent returns the QR payload for a client.
func (s *ClientService) QRContent(ctx context.Context, vpnName, clientName string) (string, error) {
	return s.root.clientQRContent(ctx, vpnName, clientName)
}

// RotatePassword rotates a client password and returns the updated URI.
func (s *ClientService) RotatePassword(ctx context.Context, vpnName, clientName string) (string, string, error) {
	return s.root.rotateClientPassword(ctx, vpnName, clientName)
}

// AddClient delegates to ClientService for backward compatibility.
func (s *Service) AddClient(ctx context.Context, in AddClientInput, reapply bool) (*domain.Client, string, error) {
	return s.Clients.Add(ctx, in, reapply)
}

// UpdateClient delegates to ClientService for backward compatibility.
func (s *Service) UpdateClient(ctx context.Context, in UpdateClientInput, reapply bool) (*domain.Client, error) {
	return s.Clients.Update(ctx, in, reapply)
}

// RemoveClient delegates to ClientService for backward compatibility.
func (s *Service) RemoveClient(ctx context.Context, vpnName, clientName string) error {
	return s.Clients.Remove(ctx, vpnName, clientName)
}

// ListClients delegates to ClientService for backward compatibility.
func (s *Service) ListClients(ctx context.Context, vpnName string) ([]domain.Client, error) {
	return s.Clients.List(ctx, vpnName)
}

// ClientURI delegates to ClientService for backward compatibility.
func (s *Service) ClientURI(ctx context.Context, vpnName, clientName string) (string, error) {
	return s.Clients.URI(ctx, vpnName, clientName)
}

// ClientQRContent delegates to ClientService for backward compatibility.
func (s *Service) ClientQRContent(ctx context.Context, vpnName, clientName string) (string, error) {
	return s.Clients.QRContent(ctx, vpnName, clientName)
}

// RotateClientPassword delegates to ClientService for backward compatibility.
func (s *Service) RotateClientPassword(ctx context.Context, vpnName, clientName string) (string, string, error) {
	return s.Clients.RotatePassword(ctx, vpnName, clientName)
}

// Apply runs configuration apply use cases.
func (s *SystemService) Apply(ctx context.Context, dryRun bool) (*apply.Result, error) {
	return s.root.applyConfig(ctx, dryRun)
}

// Rollback runs configuration rollback use cases.
func (s *SystemService) Rollback(ctx context.Context) error {
	return s.root.rollbackConfig(ctx)
}

// Apply delegates to SystemService for backward compatibility.
func (s *Service) Apply(ctx context.Context, dryRun bool) (*apply.Result, error) {
	return s.System.Apply(ctx, dryRun)
}

// Rollback delegates to SystemService for backward compatibility.
func (s *Service) Rollback(ctx context.Context) error {
	return s.System.Rollback(ctx)
}

// Bootstrap runs bootstrap installation use cases.
func (s *BootstrapService) Bootstrap(ctx context.Context, opts BootstrapOptions) error {
	return s.root.bootstrap(ctx, opts)
}

// Bootstrap delegates to BootstrapService for backward compatibility.
func (s *Service) Bootstrap(ctx context.Context, opts BootstrapOptions) error {
	return s.Bootstrapper.Bootstrap(ctx, opts)
}

// CreateBackup runs backup creation use cases.
func (s *MaintenanceService) CreateBackup(ctx context.Context) (string, error) {
	return s.root.createBackup(ctx)
}

// ListBackups returns backup archives.
func (s *MaintenanceService) ListBackups(ctx context.Context) ([]BackupEntry, error) {
	return s.root.listBackups(ctx)
}

// RestoreBackup runs backup restore use cases.
func (s *MaintenanceService) RestoreBackup(ctx context.Context, archivePath string) error {
	return s.root.restoreBackup(ctx, archivePath)
}

// UninstallPlan returns the full uninstall plan.
func (s *MaintenanceService) UninstallPlan() manifest.UninstallPlan {
	return s.root.uninstallPlan()
}

// UninstallFull executes a full uninstall.
func (s *MaintenanceService) UninstallFull(ctx context.Context, wipeData bool) error {
	return s.root.uninstallFull(ctx, wipeData)
}

// CreateBackup delegates to MaintenanceService for backward compatibility.
func (s *Service) CreateBackup(ctx context.Context) (string, error) {
	return s.Maintenance.CreateBackup(ctx)
}

// ListBackups delegates to MaintenanceService for backward compatibility.
func (s *Service) ListBackups(ctx context.Context) ([]BackupEntry, error) {
	return s.Maintenance.ListBackups(ctx)
}

// RestoreBackup delegates to MaintenanceService for backward compatibility.
func (s *Service) RestoreBackup(ctx context.Context, archivePath string) error {
	return s.Maintenance.RestoreBackup(ctx, archivePath)
}

// UninstallPlan delegates to MaintenanceService for backward compatibility.
func (s *Service) UninstallPlan() manifest.UninstallPlan {
	return s.Maintenance.UninstallPlan()
}

// UninstallFull delegates to MaintenanceService for backward compatibility.
func (s *Service) UninstallFull(ctx context.Context, wipeData bool) error {
	return s.Maintenance.UninstallFull(ctx, wipeData)
}
