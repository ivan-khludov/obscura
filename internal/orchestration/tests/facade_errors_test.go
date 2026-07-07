package orchestration_test

import (
	"context"
	"testing"

	"github.com/ivan-khludov/obscura/internal/apply"
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/service"
)

func TestFacadeServiceErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("CreateVPNFromRequest service error", func(t *testing.T) {
		orch, stub := stubFacade(t)
		stub.createVPNFn = func(context.Context, orchestration.CreateVPNInput) (*service.CreateVPNResult, error) {
			return nil, errStub
		}
		_, err := orch.CreateVPNFromRequest(ctx, orchestration.CreateVPNRequest{
			Name: "main", Protocol: "socks5",
			Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080},
		})
		if err == nil {
			t.Fatal("expected create vpn error")
		}
	})

	t.Run("ValidateCreateVPNWizardStepFromRequest validation error", func(t *testing.T) {
		orch, _ := stubFacade(t)
		err := orch.ValidateCreateVPNWizardStepFromRequest(ctx, orchestration.CreateVPNRequest{
			Protocol: "socks5", HTTPTLS: true,
		}, orchestration.WizardAfterPort)
		if err == nil {
			t.Fatal("expected validation error")
		}
	})

	t.Run("EditVPNFromRequest build and service errors", func(t *testing.T) {
		orch, stub := stubFacade(t)
		_, err := orch.EditVPNFromRequest(ctx, orchestration.EditVPNRequest{
			VPNName: "vpn", Protocol: "socks5", TLSEnableRequested: true,
		})
		if err == nil {
			t.Fatal("expected tls guard error")
		}

		stub.updateVPNFn = func(context.Context, string, orchestration.UpdateVPNInput, bool) (*domain.VPN, error) {
			return nil, errStub
		}
		_, err = orch.EditVPNFromRequest(ctx, orchestration.EditVPNRequest{
			VPNName: "vpn", Protocol: "socks5",
		})
		if err == nil {
			t.Fatal("expected update vpn error")
		}
	})

	t.Run("UpdateClientFromRequest service error", func(t *testing.T) {
		orch, stub := stubFacade(t)
		stub.updateClientFn = func(context.Context, orchestration.UpdateClientInput, bool) (*domain.Client, error) {
			return nil, errStub
		}
		_, err := orch.UpdateClientFromRequest(ctx, orchestration.UpdateClientRequest{
			VPNName: "vpn", Name: "phone",
		})
		if err == nil {
			t.Fatal("expected update client error")
		}
	})

	t.Run("AddClientFromRequest service error", func(t *testing.T) {
		orch, stub := stubFacade(t)
		stub.addClientFn = func(context.Context, service.AddClientInput, bool) (*domain.Client, string, error) {
			return nil, "", errStub
		}
		_, err := orch.AddClientFromRequest(ctx, orchestration.AddClientRequest{
			VPNName: "vpn", Name: "phone",
		})
		if err == nil {
			t.Fatal("expected add client error")
		}
	})

	t.Run("ShowClientFromRequest uri and qr errors", func(t *testing.T) {
		orch, stub := stubFacade(t)
		stub.clientURIFn = func(context.Context, string, string) (string, error) {
			return "", errStub
		}
		_, err := orch.ShowClientFromRequest(ctx, orchestration.ShowClientRequest{
			VPNName: "vpn", Name: "phone",
		})
		if err == nil {
			t.Fatal("expected client uri error")
		}

		stub.clientURIFn = func(context.Context, string, string) (string, error) {
			return "uri", nil
		}
		stub.clientQRContentFn = func(context.Context, string, string) (string, error) {
			return "", errStub
		}
		_, err = orch.ShowClientFromRequest(ctx, orchestration.ShowClientRequest{
			VPNName: "vpn", Name: "phone", IncludeQR: true,
		})
		if err == nil {
			t.Fatal("expected qr error")
		}
	})

	t.Run("RotateClientPasswordFromRequest errors", func(t *testing.T) {
		orch, stub := stubFacade(t)
		stub.rotateClientPasswordFn = func(context.Context, string, string) (string, string, error) {
			return "", "", errStub
		}
		_, err := orch.RotateClientPasswordFromRequest(ctx, orchestration.RotateClientPasswordRequest{
			VPNName: "vpn", Name: "phone",
		})
		if err == nil {
			t.Fatal("expected rotate error")
		}

		stub.rotateClientPasswordFn = func(context.Context, string, string) (string, string, error) {
			return "pass", "uri", nil
		}
		stub.clientQRContentFn = func(context.Context, string, string) (string, error) {
			return "", errStub
		}
		_, err = orch.RotateClientPasswordFromRequest(ctx, orchestration.RotateClientPasswordRequest{
			VPNName: "vpn", Name: "phone", IncludeQR: true,
		})
		if err == nil {
			t.Fatal("expected rotate qr error")
		}
	})

	t.Run("SetCongestionFromRequest apply error", func(t *testing.T) {
		orch, stub := stubFacade(t)
		stub.congestionControlFn = func() string { return "cubic" }
		stub.setCongestionControlFn = func(context.Context, string) error { return errStub }
		_, err := orch.SetCongestionFromRequest(ctx, orchestration.SetCongestionRequest{Algorithm: "bbr"})
		if err == nil {
			t.Fatal("expected set congestion error")
		}
	})

	t.Run("SetCongestionFromRequest changed success", func(t *testing.T) {
		orch, stub := stubFacade(t)
		stub.congestionControlFn = func() string { return "cubic" }
		stub.setCongestionControlFn = func(context.Context, string) error { return nil }
		result, err := orch.SetCongestionFromRequest(ctx, orchestration.SetCongestionRequest{Algorithm: "bbr"})
		if err != nil {
			t.Fatalf("set congestion changed: %v", err)
		}
		if !result.Changed || result.Algorithm != "bbr" {
			t.Fatalf("unexpected result: %#v", result)
		}
	})

	t.Run("UninstallFromRequest execute error", func(t *testing.T) {
		orch, stub := stubFacade(t)
		stub.uninstallFullFn = func(context.Context, bool) error { return errStub }
		_, err := orch.UninstallFromRequest(ctx, orchestration.UninstallRequest{
			Full: true, Confirm: "destroy",
		})
		if err == nil {
			t.Fatal("expected uninstall error")
		}
	})

	t.Run("DeleteVPNFromRequest service error", func(t *testing.T) {
		orch, stub := stubFacade(t)
		stub.deleteVPNFn = func(context.Context, string) error { return errStub }
		_, err := orch.DeleteVPNFromRequest(ctx, orchestration.DeleteVPNRequest{Name: "vpn"})
		if err == nil {
			t.Fatal("expected delete vpn error")
		}
	})

	t.Run("ListVPNsFromRequest service error", func(t *testing.T) {
		orch, stub := stubFacade(t)
		stub.listVPNsFn = func(context.Context) ([]domain.VPN, error) { return nil, errStub }
		_, err := orch.ListVPNsFromRequest(ctx, orchestration.ListVPNsRequest{})
		if err == nil {
			t.Fatal("expected list vpns error")
		}
	})

	t.Run("GetVPNFromRequest service error", func(t *testing.T) {
		orch, stub := stubFacade(t)
		stub.getVPNFn = func(context.Context, string) (*domain.VPN, error) { return nil, errStub }
		_, err := orch.GetVPNFromRequest(ctx, orchestration.GetVPNRequest{Name: "vpn"})
		if err == nil {
			t.Fatal("expected get vpn error")
		}
	})

	t.Run("RemoveClientFromRequest blank client and service error", func(t *testing.T) {
		orch, stub := stubFacade(t)
		if _, err := orch.RemoveClientFromRequest(ctx, orchestration.RemoveClientRequest{
			VPNName: "   ", Name: "phone",
		}); err == nil {
			t.Fatal("expected blank vpn error")
		}
		if _, err := orch.RemoveClientFromRequest(ctx, orchestration.RemoveClientRequest{
			VPNName: "vpn", Name: "   ",
		}); err == nil {
			t.Fatal("expected blank client error")
		}
		stub.removeClientFn = func(context.Context, string, string) error { return errStub }
		_, err := orch.RemoveClientFromRequest(ctx, orchestration.RemoveClientRequest{
			VPNName: "vpn", Name: "phone",
		})
		if err == nil {
			t.Fatal("expected remove client error")
		}
	})

	t.Run("ListClientsFromRequest service error", func(t *testing.T) {
		orch, stub := stubFacade(t)
		stub.listClientsFn = func(context.Context, string) ([]domain.Client, error) {
			return nil, errStub
		}
		_, err := orch.ListClientsFromRequest(ctx, orchestration.ListClientsRequest{VPNName: "vpn"})
		if err == nil {
			t.Fatal("expected list clients error")
		}
	})

	t.Run("BootstrapFromRequest error and nil progress", func(t *testing.T) {
		orch, stub := stubFacade(t)
		stub.bootstrapFn = func(_ context.Context, opts service.BootstrapOptions) error {
			if opts.Progress != nil {
				opts.Progress(service.BootstrapProgress{Label: "stage", Percent: 10})
			}
			return nil
		}
		if _, err := orch.BootstrapFromRequest(ctx, orchestration.BootstrapRequest{}); err != nil {
			t.Fatalf("bootstrap with nil progress: %v", err)
		}

		stub.bootstrapFn = func(context.Context, service.BootstrapOptions) error { return errStub }
		_, err := orch.BootstrapFromRequest(ctx, orchestration.BootstrapRequest{})
		if err == nil {
			t.Fatal("expected bootstrap error")
		}
	})

	t.Run("ApplyFromRequest service error", func(t *testing.T) {
		orch, stub := stubFacade(t)
		stub.applyFn = func(context.Context, bool) (*apply.Result, error) { return nil, errStub }
		_, err := orch.ApplyFromRequest(ctx, orchestration.ApplyRequest{DryRun: true})
		if err == nil {
			t.Fatal("expected apply error")
		}
	})

	t.Run("RollbackFromRequest success and error", func(t *testing.T) {
		orch, stub := stubFacade(t)
		stub.rollbackFn = func(context.Context) error { return nil }
		result, err := orch.RollbackFromRequest(ctx, orchestration.RollbackRequest{})
		if err != nil || !result.RolledBack {
			t.Fatalf("rollback success: err=%v result=%#v", err, result)
		}

		stub.rollbackFn = func(context.Context) error { return errStub }
		_, err = orch.RollbackFromRequest(ctx, orchestration.RollbackRequest{})
		if err == nil {
			t.Fatal("expected rollback error")
		}
	})

	t.Run("StatusFromRequest service error", func(t *testing.T) {
		orch, stub := stubFacade(t)
		stub.statusFn = func(context.Context) (*service.StatusSummary, error) { return nil, errStub }
		_, err := orch.StatusFromRequest(ctx, orchestration.StatusRequest{})
		if err == nil {
			t.Fatal("expected status error")
		}
	})

	t.Run("CreateBackupFromRequest service error", func(t *testing.T) {
		orch, stub := stubFacade(t)
		stub.createBackupFn = func(context.Context) (string, error) { return "", errStub }
		_, err := orch.CreateBackupFromRequest(ctx, orchestration.CreateBackupRequest{})
		if err == nil {
			t.Fatal("expected create backup error")
		}
	})

	t.Run("ListBackupsFromRequest service error", func(t *testing.T) {
		orch, stub := stubFacade(t)
		stub.listBackupsFn = func(context.Context) ([]service.BackupEntry, error) { return nil, errStub }
		_, err := orch.ListBackupsFromRequest(ctx, orchestration.ListBackupsRequest{})
		if err == nil {
			t.Fatal("expected list backups error")
		}
	})

	t.Run("RestoreBackupFromRequest service error", func(t *testing.T) {
		orch, stub := stubFacade(t)
		stub.restoreBackupFn = func(context.Context, string) error { return errStub }
		_, err := orch.RestoreBackupFromRequest(ctx, orchestration.RestoreBackupRequest{ArchivePath: "/tmp/x.tar"})
		if err == nil {
			t.Fatal("expected restore backup error")
		}
	})

	t.Run("SetSSHPortFromRequest service error", func(t *testing.T) {
		orch, stub := stubFacade(t)
		stub.sshPortFn = func() int { return 22 }
		stub.setSSHPortFn = func(context.Context, int) error { return errStub }
		_, err := orch.SetSSHPortFromRequest(ctx, orchestration.SetSSHPortRequest{Port: 2222})
		if err == nil {
			t.Fatal("expected set ssh port error")
		}
	})

	t.Run("ValidateVPNListenPortFromRequest invalid port", func(t *testing.T) {
		orch, _ := stubFacade(t)
		if err := orch.ValidateVPNListenPortFromRequest(ctx, orchestration.ValidateVPNListenPortRequest{Port: 0}); err == nil {
			t.Fatal("expected invalid port error")
		}
	})

	t.Run("ValidateVPNNameFromRequest service error", func(t *testing.T) {
		orch, stub := stubFacade(t)
		stub.validateVPNNameFn = func(context.Context, string) error { return errStub }
		if err := orch.ValidateVPNNameFromRequest(ctx, orchestration.ValidateVPNNameRequest{Name: "valid"}); err == nil {
			t.Fatal("expected validate vpn name service error")
		}
	})

	t.Run("ValidateVPNListenPortFromRequest service error", func(t *testing.T) {
		orch, stub := stubFacade(t)
		stub.validateVPNListenPortFn = func(context.Context, int) error { return errStub }
		if err := orch.ValidateVPNListenPortFromRequest(ctx, orchestration.ValidateVPNListenPortRequest{Port: 8080}); err == nil {
			t.Fatal("expected validate vpn listen port service error")
		}
	})
}
