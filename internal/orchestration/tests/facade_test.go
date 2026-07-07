package orchestration_test

import (
	"context"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/doctor"
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/protocol/vless"
	"github.com/ivan-khludov/obscura/internal/runtime"
)

func newTestFacade(t *testing.T) *orchestration.Facade {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	orch, _, cleanup, err := runtime.OpenWithOrchestration(true)
	if err != nil {
		t.Fatalf("open runtime with orchestration: %v", err)
	}
	t.Cleanup(cleanup)
	return orch
}

func newTestFacadeWithBackend(t *testing.T) orchestration.Backend {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	svc, _, cleanup, err := runtime.Open(true)
	if err != nil {
		t.Fatalf("open runtime service: %v", err)
	}
	t.Cleanup(cleanup)
	return svc
}

func TestCreateVPNFromRequest_RunsPipeline(t *testing.T) {
	orch := newTestFacade(t)
	ctx := context.Background()

	req := orchestration.CreateVPNRequest{
		Name:              "main",
		Protocol:          "socks5",
		Enabled:           true,
		Listen:            domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080},
		InitialClientName: "phone",
	}
	result, err := orch.CreateVPNFromRequest(ctx, req)
	if err != nil {
		t.Fatalf("create vpn from request: %v", err)
	}
	if result == nil || result.VPN == nil {
		t.Fatal("expected created vpn result")
	}
	if result.VPN.Name != "main" {
		t.Fatalf("expected vpn name main, got %q", result.VPN.Name)
	}
}

func TestCreateVPNFromRequest_RejectsAffinityMismatch(t *testing.T) {
	orch := newTestFacade(t)
	ctx := context.Background()

	_, err := orch.CreateVPNFromRequest(ctx, orchestration.CreateVPNRequest{
		Name:        "bad",
		Protocol:    "trojan",
		SSMethod:    "2022-blake3-aes-128-gcm",
		SSShadowTLS: true,
	})
	if err == nil {
		t.Fatal("expected mismatch error from orchestration validation")
	}
}

func TestValidateCreateVPNWizardStepFromRequest(t *testing.T) {
	orch := newTestFacade(t)
	ctx := context.Background()

	err := orch.ValidateCreateVPNWizardStepFromRequest(ctx, orchestration.CreateVPNRequest{
		Name:     "draft",
		Protocol: "http",
		Listen:   domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 8080},
		HTTP:     orchestration.HTTPCreateOptions{TLS: true},
		HTTPTLS:  true,
	}, orchestration.WizardAfterPort)
	if err != nil {
		t.Fatalf("validate wizard step from request: %v", err)
	}
}

func TestValidateCreateVPNWizardStepFromRequest_ServiceError(t *testing.T) {
	orch := newTestFacade(t)
	ctx := context.Background()

	err := orch.ValidateCreateVPNWizardStepFromRequest(ctx, orchestration.CreateVPNRequest{
		Name:     "vl",
		Protocol: "vless",
		Listen:   domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1443},
		VLESS: orchestration.VLESSCreateOptions{
			DefaultFlow: vless.FlowVision,
			Transport:   "grpc",
			ServerName:  "example.com",
		},
		Trojan: orchestration.TrojanCreateOptions{
			Transport:  "grpc",
			ServerName: "example.com",
		},
	}, orchestration.WizardAfterTransport)
	if err == nil {
		t.Fatal("expected wizard validation error")
	}
	if !strings.Contains(err.Error(), "wizard step") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEditAndClientRequestMethods(t *testing.T) {
	orch := newTestFacade(t)
	ctx := context.Background()

	created, err := orch.CreateVPNFromRequest(ctx, orchestration.CreateVPNRequest{
		Name:              "vpn",
		Protocol:          "socks5",
		Enabled:           true,
		Listen:            domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080},
		InitialClientName: "phone",
	})
	if err != nil {
		t.Fatalf("create vpn: %v", err)
	}

	added, err := orch.AddClientFromRequest(ctx, orchestration.AddClientRequest{
		VPNName: "vpn",
		Name:    "laptop",
		Reapply: true,
	})
	if err != nil {
		t.Fatalf("add client from request: %v", err)
	}
	if added.Client.Name != "laptop" {
		t.Fatalf("expected laptop client, got %q", added.Client.Name)
	}

	newClientName := "tablet"
	updatedClient, err := orch.UpdateClientFromRequest(ctx, orchestration.UpdateClientRequest{
		VPNName: "vpn",
		Name:    "laptop",
		NewName: &newClientName,
		Reapply: true,
	})
	if err != nil {
		t.Fatalf("update client from request: %v", err)
	}
	if updatedClient.Client.Name != "tablet" {
		t.Fatalf("expected renamed client tablet, got %q", updatedClient.Client.Name)
	}

	newVPNName := "vpn-new"
	updatedVPN, err := orch.EditVPNFromRequest(ctx, orchestration.EditVPNRequest{
		VPNName:  created.VPN.Name,
		Protocol: created.VPN.Protocol,
		Update: orchestration.UpdateVPNRequest{
			Name: &newVPNName,
		},
		Reapply: true,
	})
	if err != nil {
		t.Fatalf("edit vpn from request: %v", err)
	}
	if updatedVPN.VPN.Name != "vpn-new" {
		t.Fatalf("expected renamed vpn vpn-new, got %q", updatedVPN.VPN.Name)
	}
}

func TestShowAndRotateClientFromRequest(t *testing.T) {
	orch := newTestFacade(t)
	ctx := context.Background()

	_, err := orch.CreateVPNFromRequest(ctx, orchestration.CreateVPNRequest{
		Name:              "vpn",
		Protocol:          "socks5",
		Enabled:           true,
		Listen:            domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080},
		InitialClientName: "phone",
	})
	if err != nil {
		t.Fatalf("create vpn: %v", err)
	}

	shown, err := orch.ShowClientFromRequest(ctx, orchestration.ShowClientRequest{
		VPNName:   "vpn",
		Name:      "phone",
		IncludeQR: true,
	})
	if err != nil {
		t.Fatalf("show client from request: %v", err)
	}
	if shown.URI == "" {
		t.Fatal("expected non-empty uri")
	}
	if shown.QRContent == "" {
		t.Fatal("expected non-empty qr content")
	}

	noQR, err := orch.ShowClientFromRequest(ctx, orchestration.ShowClientRequest{
		VPNName:   "vpn",
		Name:      "phone",
		IncludeQR: false,
	})
	if err != nil {
		t.Fatalf("show client without qr: %v", err)
	}
	if noQR.URI == "" || noQR.QRContent != "" {
		t.Fatalf("expected uri without qr, got %#v", noQR)
	}

	rotated, err := orch.RotateClientPasswordFromRequest(ctx, orchestration.RotateClientPasswordRequest{
		VPNName:   "vpn",
		Name:      "phone",
		IncludeQR: true,
	})
	if err != nil {
		t.Fatalf("rotate client from request: %v", err)
	}
	if rotated.Password == "" || rotated.URI == "" || rotated.QRContent == "" {
		t.Fatalf("expected password/uri/qr after rotation, got %#v", rotated)
	}

	noQRRotate, err := orch.RotateClientPasswordFromRequest(ctx, orchestration.RotateClientPasswordRequest{
		VPNName:   "vpn",
		Name:      "phone",
		IncludeQR: false,
	})
	if err != nil {
		t.Fatalf("rotate without qr: %v", err)
	}
	if noQRRotate.QRContent != "" {
		t.Fatal("expected empty qr content")
	}
}

func TestShowClientFromRequest_AllowQRFallback(t *testing.T) {
	base := newTestFacadeWithBackend(t)
	stub := newDelegatingBackend(base)
	stub.clientURIFn = func(_ context.Context, _, _ string) (string, error) {
		return "uri://test", nil
	}
	stub.clientQRContentFn = func(_ context.Context, _, _ string) (string, error) {
		return "", errStub
	}
	orch := orchestration.NewWithBackend(stub)
	ctx := context.Background()

	out, err := orch.ShowClientFromRequest(ctx, orchestration.ShowClientRequest{
		VPNName:         "vpn",
		Name:            "phone",
		IncludeQR:       true,
		AllowQRFallback: true,
	})
	if err != nil {
		t.Fatalf("show client with qr fallback: %v", err)
	}
	if out.URI != "uri://test" || out.QRContent != "" {
		t.Fatalf("unexpected fallback result: %#v", out)
	}

	_, err = orch.ShowClientFromRequest(ctx, orchestration.ShowClientRequest{
		VPNName:   "vpn",
		Name:      "phone",
		IncludeQR: true,
	})
	if err == nil {
		t.Fatal("expected qr error without fallback")
	}
}

func TestCongestionAndUninstallFromRequest(t *testing.T) {
	orch := newTestFacade(t)
	ctx := context.Background()

	congestion, err := orch.NetworkCongestionFromRequest(ctx, orchestration.NetworkCongestionRequest{})
	if err != nil {
		t.Fatalf("network congestion from request: %v", err)
	}
	if congestion.Current == "" || len(congestion.Available) == 0 {
		t.Fatalf("expected congestion data, got %#v", congestion)
	}

	if _, err := orch.SetCongestionFromRequest(ctx, orchestration.SetCongestionRequest{}); err == nil {
		t.Fatal("expected empty algorithm error")
	}

	noop, err := orch.SetCongestionFromRequest(ctx, orchestration.SetCongestionRequest{Algorithm: congestion.Current})
	if err != nil {
		t.Fatalf("set congestion no-op: %v", err)
	}
	if noop.Changed {
		t.Fatalf("expected no-op congestion update for current algorithm")
	}

	for _, alg := range congestion.Available {
		if alg == congestion.Current {
			continue
		}
		_, err := orch.SetCongestionFromRequest(ctx, orchestration.SetCongestionRequest{Algorithm: alg})
		if err == nil {
			t.Fatal("expected dev-mode congestion apply error")
		}
		break
	}

	preview, err := orch.UninstallFromRequest(ctx, orchestration.UninstallRequest{DryRun: true})
	if err != nil {
		t.Fatalf("uninstall dry-run from request: %v", err)
	}
	if preview == nil || preview.Executed {
		t.Fatalf("expected non-executed dry-run result, got %#v", preview)
	}

	if _, err := orch.UninstallFromRequest(ctx, orchestration.UninstallRequest{}); err == nil {
		t.Fatal("expected full flag error")
	}
	if _, err := orch.UninstallFromRequest(ctx, orchestration.UninstallRequest{Full: true}); err == nil {
		t.Fatal("expected confirm destroy error")
	}
}

func TestUninstallFromRequest_Executed(t *testing.T) {
	base := newTestFacadeWithBackend(t)
	stub := newDelegatingBackend(base)
	stub.uninstallFullFn = func(context.Context, bool) error { return nil }
	orch := orchestration.NewWithBackend(stub)
	ctx := context.Background()

	executed, err := orch.UninstallFromRequest(ctx, orchestration.UninstallRequest{
		Full:    true,
		Confirm: "destroy",
	})
	if err != nil {
		t.Fatalf("uninstall full: %v", err)
	}
	if !executed.Executed {
		t.Fatal("expected executed uninstall")
	}
}

func TestNetworkCongestionFromRequest_ListError(t *testing.T) {
	base := newTestFacadeWithBackend(t)
	stub := newDelegatingBackend(base)
	stub.listCongestionControlsFn = func() ([]string, error) {
		return nil, errStub
	}
	orch := orchestration.NewWithBackend(stub)

	_, err := orch.NetworkCongestionFromRequest(context.Background(), orchestration.NetworkCongestionRequest{})
	if err == nil {
		t.Fatal("expected list congestion error")
	}
}

func TestSystemRequestFirstWorkflows(t *testing.T) {
	orch := newTestFacade(t)
	ctx := context.Background()

	status, err := orch.StatusFromRequest(ctx, orchestration.StatusRequest{})
	if err != nil {
		t.Fatalf("status from request: %v", err)
	}
	if status.ObscuraVersion == "" {
		t.Fatal("expected non-empty obscura version")
	}

	if _, err := orch.ApplyFromRequest(ctx, orchestration.ApplyRequest{
		RequireBootstrapped: true,
	}); err == nil {
		t.Fatal("expected bootstrap required error for apply")
	}

	applyResult, err := orch.ApplyFromRequest(ctx, orchestration.ApplyRequest{DryRun: true})
	if err != nil {
		t.Fatalf("apply from request dry-run: %v", err)
	}
	if applyResult == nil {
		t.Fatal("expected non-nil apply result")
	}

	if _, err := orch.RollbackFromRequest(ctx, orchestration.RollbackRequest{RequireBootstrapped: true}); err == nil {
		t.Fatal("expected bootstrap required error for rollback")
	}
	if _, err := orch.RollbackFromRequest(ctx, orchestration.RollbackRequest{}); err == nil {
		t.Fatal("expected rollback error when no backup exists")
	}

	createdBackup, err := orch.CreateBackupFromRequest(ctx, orchestration.CreateBackupRequest{})
	if err != nil {
		t.Fatalf("create backup from request: %v", err)
	}
	if createdBackup.Path == "" {
		t.Fatal("expected backup path")
	}

	backupList, err := orch.ListBackupsFromRequest(ctx, orchestration.ListBackupsRequest{})
	if err != nil {
		t.Fatalf("list backups from request: %v", err)
	}
	if len(backupList.Entries) == 0 {
		t.Fatal("expected non-empty backups list after backup creation")
	}

	restored, err := orch.RestoreBackupFromRequest(ctx, orchestration.RestoreBackupRequest{
		ArchivePath: createdBackup.Path,
	})
	if err != nil {
		t.Fatalf("restore backup from request: %v", err)
	}
	if !restored.Restored {
		t.Fatal("expected restored=true")
	}
}

func TestBootstrapAndListWorkflows(t *testing.T) {
	orch := newTestFacade(t)
	ctx := context.Background()

	before, err := orch.GetBootstrapStatusFromRequest(ctx, orchestration.BootstrapStatusRequest{})
	if err != nil {
		t.Fatalf("bootstrap status: %v", err)
	}

	var progressSeen bool
	_, err = orch.BootstrapFromRequest(ctx, orchestration.BootstrapRequest{
		Progress: func(p orchestration.BootstrapProgress) {
			progressSeen = true
			if p.Label == "" {
				t.Fatal("expected progress label")
			}
		},
	})
	if err != nil {
		t.Fatalf("bootstrap from request: %v", err)
	}
	if !progressSeen {
		t.Fatal("expected bootstrap progress callback")
	}

	after, err := orch.GetBootstrapStatusFromRequest(ctx, orchestration.BootstrapStatusRequest{})
	if err != nil {
		t.Fatalf("bootstrap status after: %v", err)
	}
	if before.Bootstrapped || !after.Bootstrapped {
		t.Fatalf("bootstrapped before=%v after=%v", before.Bootstrapped, after.Bootstrapped)
	}

	protocols, err := orch.ListProtocolsFromRequest(ctx, orchestration.ProtocolListRequest{})
	if err != nil {
		t.Fatalf("list protocols: %v", err)
	}
	if len(protocols.Names) == 0 {
		t.Fatal("expected protocols")
	}
}

func TestVPNListAndGetWorkflows(t *testing.T) {
	orch := newTestFacade(t)
	ctx := context.Background()

	_, err := orch.CreateVPNFromRequest(ctx, orchestration.CreateVPNRequest{
		Name:              "alpha",
		Protocol:          "socks5",
		Enabled:           true,
		Listen:            domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080},
		InitialClientName: "phone",
	})
	if err != nil {
		t.Fatalf("create alpha: %v", err)
	}
	_, err = orch.CreateVPNFromRequest(ctx, orchestration.CreateVPNRequest{
		Name:              "beta",
		Protocol:          "socks5",
		Enabled:           true,
		Listen:            domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1081},
		InitialClientName: "phone",
	})
	if err != nil {
		t.Fatalf("create beta: %v", err)
	}

	listed, err := orch.ListVPNsFromRequest(ctx, orchestration.ListVPNsRequest{})
	if err != nil {
		t.Fatalf("list vpns: %v", err)
	}
	if len(listed.Items) < 2 || listed.Items[0].Name != "alpha" {
		t.Fatalf("expected sorted vpns, got %#v", listed.Items)
	}

	got, err := orch.GetVPNFromRequest(ctx, orchestration.GetVPNRequest{Name: "beta"})
	if err != nil {
		t.Fatalf("get vpn: %v", err)
	}
	if got.VPN.Name != "beta" {
		t.Fatalf("expected beta, got %q", got.VPN.Name)
	}

	clients, err := orch.ListClientsFromRequest(ctx, orchestration.ListClientsRequest{VPNName: "alpha"})
	if err != nil {
		t.Fatalf("list clients: %v", err)
	}
	if len(clients.Items) == 0 {
		t.Fatal("expected clients")
	}

	_, err = orch.AddClientFromRequest(ctx, orchestration.AddClientRequest{
		VPNName: "alpha",
		Name:    "laptop",
	})
	if err != nil {
		t.Fatalf("add second client: %v", err)
	}
	clients, err = orch.ListClientsFromRequest(ctx, orchestration.ListClientsRequest{VPNName: "alpha"})
	if err != nil {
		t.Fatalf("list clients again: %v", err)
	}
	if len(clients.Items) < 2 || clients.Items[0].Name != "laptop" {
		t.Fatalf("expected sorted clients, got %#v", clients.Items)
	}
}

func TestDeleteAndRemoveWorkflows(t *testing.T) {
	orch := newTestFacade(t)
	ctx := context.Background()

	_, err := orch.CreateVPNFromRequest(ctx, orchestration.CreateVPNRequest{
		Name:              "vpn",
		Protocol:          "socks5",
		Enabled:           true,
		Listen:            domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080},
		InitialClientName: "phone",
	})
	if err != nil {
		t.Fatalf("create vpn: %v", err)
	}
	_, err = orch.AddClientFromRequest(ctx, orchestration.AddClientRequest{
		VPNName: "vpn",
		Name:    "laptop",
	})
	if err != nil {
		t.Fatalf("add client: %v", err)
	}

	removed, err := orch.RemoveClientFromRequest(ctx, orchestration.RemoveClientRequest{
		VPNName: "vpn",
		Name:    "laptop",
	})
	if err != nil {
		t.Fatalf("remove client: %v", err)
	}
	if !removed.Removed {
		t.Fatal("expected removed=true")
	}

	deleted, err := orch.DeleteVPNFromRequest(ctx, orchestration.DeleteVPNRequest{Name: "vpn"})
	if err != nil {
		t.Fatalf("delete vpn: %v", err)
	}
	if !deleted.Deleted {
		t.Fatal("expected deleted=true")
	}
}

func TestSSHPortWorkflows(t *testing.T) {
	orch := newTestFacade(t)
	ctx := context.Background()

	current, err := orch.GetSSHPortFromRequest(ctx, orchestration.SSHPortReadRequest{})
	if err != nil {
		t.Fatalf("get ssh port: %v", err)
	}
	if current.Port <= 0 {
		t.Fatal("expected positive ssh port")
	}

	unchanged, err := orch.SetSSHPortFromRequest(ctx, orchestration.SetSSHPortRequest{Port: current.Port})
	if err != nil {
		t.Fatalf("set ssh port noop: %v", err)
	}
	if unchanged.Changed {
		t.Fatal("expected unchanged ssh port")
	}

	base := newTestFacadeWithBackend(t)
	stubBackend := newDelegatingBackend(base)
	newPort := current.Port + 1
	if newPort > 65535 {
		newPort = current.Port - 1
	}
	stubBackend.setSSHPortFn = func(_ context.Context, port int) error {
		if port != newPort {
			t.Fatalf("unexpected port %d", port)
		}
		return nil
	}
	changedOrch := orchestration.NewWithBackend(stubBackend)

	changed, err := changedOrch.SetSSHPortFromRequest(ctx, orchestration.SetSSHPortRequest{Port: newPort})
	if err != nil {
		t.Fatalf("set ssh port changed: %v", err)
	}
	if !changed.Changed || changed.Port != newPort {
		t.Fatalf("expected changed port %d, got %#v", newPort, changed)
	}
}

func TestDoctorFromRequest(t *testing.T) {
	orch := newTestFacade(t)
	ctx := context.Background()

	results, err := orch.DoctorFromRequest(ctx, orchestration.DoctorRequest{})
	if err != nil {
		t.Fatalf("doctor: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected doctor results")
	}

	base := newTestFacadeWithBackend(t)
	stub := newDelegatingBackend(base)
	failOrch := orchestration.NewWithBackend(&doctorFailBackend{delegatingBackend: stub})
	_, err = failOrch.DoctorFromRequest(ctx, orchestration.DoctorRequest{FailOnFailures: true})
	if err == nil {
		t.Fatal("expected doctor failure error")
	}

	_, err = failOrch.DoctorFromRequest(ctx, orchestration.DoctorRequest{FailOnFailures: false})
	if err != nil {
		t.Fatalf("doctor without fail-on-failures: %v", err)
	}
}

type doctorFailBackend struct {
	*delegatingBackend
}

func (d *doctorFailBackend) Doctor(_ context.Context) []doctor.CheckResult {
	return []doctor.CheckResult{{Name: "test", Status: doctor.StatusFail}}
}

func TestMutationRequestPolicies(t *testing.T) {
	orch := newTestFacade(t)
	ctx := context.Background()

	if _, err := orch.DeleteVPNFromRequest(ctx, orchestration.DeleteVPNRequest{}); err == nil {
		t.Fatal("expected vpn delete request validation error")
	}
	if _, err := orch.RemoveClientFromRequest(ctx, orchestration.RemoveClientRequest{VPNName: "vpn"}); err == nil {
		t.Fatal("expected remove client request validation error")
	}
	if _, err := orch.RestoreBackupFromRequest(ctx, orchestration.RestoreBackupRequest{}); err == nil {
		t.Fatal("expected restore backup request validation error")
	}
	if _, err := orch.SetSSHPortFromRequest(ctx, orchestration.SetSSHPortRequest{Port: 0}); err == nil {
		t.Fatal("expected set ssh port request validation error")
	}
}

func TestReadAndValidationRequestPolicies(t *testing.T) {
	orch := newTestFacade(t)
	ctx := context.Background()

	if _, err := orch.GetVPNFromRequest(ctx, orchestration.GetVPNRequest{Name: "   "}); err == nil {
		t.Fatal("expected get vpn request validation error for blank name")
	}
	if _, err := orch.ListClientsFromRequest(ctx, orchestration.ListClientsRequest{VPNName: "   "}); err == nil {
		t.Fatal("expected list clients request validation error for blank vpn")
	}
	if err := orch.ValidateVPNNameFromRequest(ctx, orchestration.ValidateVPNNameRequest{Name: "   "}); err == nil {
		t.Fatal("expected validate vpn name request validation error for blank name")
	}
	if err := orch.ValidateVPNListenPortFromRequest(ctx, orchestration.ValidateVPNListenPortRequest{Port: 70000}); err == nil {
		t.Fatal("expected validate vpn listen port validation error for out-of-range port")
	}

	_, err := orch.CreateVPNFromRequest(ctx, orchestration.CreateVPNRequest{
		Name:              "dup",
		Protocol:          "socks5",
		Enabled:           true,
		Listen:            domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 1080},
		InitialClientName: "phone",
	})
	if err != nil {
		t.Fatalf("create vpn: %v", err)
	}
	if err := orch.ValidateVPNNameFromRequest(ctx, orchestration.ValidateVPNNameRequest{Name: "dup"}); err == nil {
		t.Fatal("expected duplicate vpn name validation error")
	}
	if err := orch.ValidateVPNListenPortFromRequest(ctx, orchestration.ValidateVPNListenPortRequest{Port: 1080}); err == nil {
		t.Fatal("expected port-in-use validation error")
	}
	if err := orch.ValidateVPNNameFromRequest(ctx, orchestration.ValidateVPNNameRequest{Name: "fresh-name"}); err != nil {
		t.Fatalf("validate fresh vpn name: %v", err)
	}
	if err := orch.ValidateVPNListenPortFromRequest(ctx, orchestration.ValidateVPNListenPortRequest{Port: 9090}); err != nil {
		t.Fatalf("validate unused listen port: %v", err)
	}
}

func TestNewWithBackend(t *testing.T) {
	base := newTestFacadeWithBackend(t)
	if orchestration.NewWithBackend(base) == nil {
		t.Fatal("expected non-nil facade")
	}
}
