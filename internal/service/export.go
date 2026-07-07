package service

import (
	"context"

	"github.com/ivan-khludov/obscura/internal/doctor"
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/install"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/protocol/httpproxy"
	"github.com/ivan-khludov/obscura/internal/render"
	"github.com/ivan-khludov/obscura/internal/sshd"
	"github.com/ivan-khludov/obscura/internal/sysctl"
	"github.com/ivan-khludov/obscura/internal/systemd"
)

// NeedsInitialClientForTest exposes needsInitialClient for external tests.
func NeedsInitialClientForTest(adapter protocol.Protocol, vpn domain.VPNConfig) bool {
	return needsInitialClient(adapter, vpn)
}

// ToVPNConfigForTest exposes toVPNConfig for external tests.
func ToVPNConfigForTest(vpn *domain.VPN) domain.VPNConfig {
	return toVPNConfig(vpn)
}

// ToClientConfigsForTest exposes toClientConfigs for external tests.
func ToClientConfigsForTest(clients []domain.Client) []domain.ClientConfig {
	return toClientConfigs(clients)
}

// SSOptionSetForTest exposes ssOptionSet for external tests.
func SSOptionSetForTest(in CreateVPNInput) bool {
	return ssOptionSet(in)
}

// SanitizeNameForTest exposes sanitizeName for external tests.
func SanitizeNameForTest(name string) string {
	return sanitizeName(name)
}

// RandomPasswordForTest exposes randomPassword for external tests.
func RandomPasswordForTest(g *PasswordGen, n int) (string, error) {
	if g == nil {
		g = &PasswordGen{}
	}
	return g.randomPassword(n)
}

// CreateSpecForTest exposes createSpec for external tests.
func CreateSpecForTest(in CreateVPNInput) domain.CreateVPNSpec {
	return createSpec(in)
}

// ProtocolOptionsFromInputForTest exposes protocolOptionsFromInput for external tests.
func ProtocolOptionsFromInputForTest(in CreateVPNInput) any {
	return protocolOptionsFromInput(in)
}

// HasHTTPOptionsForTest exposes hasHTTPOptions for external tests.
func HasHTTPOptionsForTest(v HTTPCreateOptions) bool {
	return hasHTTPOptions(v)
}

// HasShadowsocksOptionsForTest exposes hasShadowsocksOptions for external tests.
func HasShadowsocksOptionsForTest(v ShadowsocksCreateOptions) bool {
	return hasShadowsocksOptions(v)
}

// PreviewTagForTest exposes previewTag for external tests.
func PreviewTagForTest(name string) string {
	return previewTag(name)
}

// PreviewNameForTest exposes previewName for external tests.
func PreviewNameForTest(name string) string {
	return previewName(name)
}

// ValidateCreateVPNInputFieldsForTest exposes validateCreateVPNInputFields for external tests.
func ValidateCreateVPNInputFieldsForTest(in CreateVPNInput) error {
	return validateCreateVPNInputFields(in)
}

// ValidateStructuredProtocolOptionOwnershipForTest exposes validateStructuredProtocolOptionOwnership for external tests.
func ValidateStructuredProtocolOptionOwnershipForTest(in CreateVPNInput) error {
	return validateStructuredProtocolOptionOwnership(in)
}

// ListenProtosForVPNForTest exposes listenProtosForVPN for external tests.
func ListenProtosForVPNForTest(vpn domain.VPN) []string {
	return listenProtosForVPN(vpn)
}

// TrojanTransportIsQUICForTest exposes trojanTransportIsQUIC for external tests.
func TrojanTransportIsQUICForTest(raw []byte) bool {
	return trojanTransportIsQUIC(raw)
}

// VmessTransportIsQUICForTest exposes vmessTransportIsQUIC for external tests.
func VmessTransportIsQUICForTest(raw []byte) bool {
	return vmessTransportIsQUIC(raw)
}

// UsesLocalFallbackStubForTest exposes usesLocalFallbackStub for external tests.
func UsesLocalFallbackStubForTest(vpn domain.VPN) bool {
	return usesLocalFallbackStub(vpn)
}

// FirewallRuleSpecsForTest exposes firewallRuleSpecs for external tests.
func FirewallRuleSpecsForTest(port int, protos []string) []string {
	return firewallRuleSpecs(port, protos)
}

// GenerateWireguardClientCredentialsForTest exposes generateWireguardClientCredentials for external tests.
func (s *Service) GenerateWireguardClientCredentialsForTest() (string, string, error) {
	return s.generateWireguardClientCredentials()
}

// ReportBootstrapProgressForTest exposes reportBootstrapProgress for external tests.
func ReportBootstrapProgressForTest(opts BootstrapOptions, label string, percent int) {
	reportBootstrapProgress(opts, label, percent)
}

// FormatDownloadProgressForTest exposes formatDownloadProgress for external tests.
func FormatDownloadProgressForTest(read, total int64) string {
	return formatDownloadProgress(read, total)
}

// FormatByteSizeForTest exposes formatByteSize for external tests.
func FormatByteSizeForTest(n int64) string {
	return formatByteSize(n)
}

// BuildListenChecksForTest exposes buildListenChecks for external tests.
func (s *Service) BuildListenChecksForTest(ctx context.Context) []doctor.ListenCheck {
	return s.buildListenChecks(ctx)
}

// RemoveVPNCertsForTest exposes removeVPNCerts for external tests.
func (s *Service) RemoveVPNCertsForTest(vpn *domain.VPN) {
	s.removeVPNCerts(vpn)
}

// RemoveHTTPCertsForTest exposes removeHTTPCerts for external tests.
func (s *Service) RemoveHTTPCertsForTest(vpn *domain.VPN) {
	s.removeHTTPCerts(vpn)
}

// RemoveTrojanCertsForTest exposes removeTrojanCerts for external tests.
func (s *Service) RemoveTrojanCertsForTest(vpn *domain.VPN) {
	s.removeTrojanCerts(vpn)
}

// RemoveVmessCertsForTest exposes removeVmessCerts for external tests.
func (s *Service) RemoveVmessCertsForTest(vpn *domain.VPN) {
	s.removeVmessCerts(vpn)
}

// RemoveVlessCertsForTest exposes removeVlessCerts for external tests.
func (s *Service) RemoveVlessCertsForTest(vpn *domain.VPN) {
	s.removeVlessCerts(vpn)
}

// RemoveHysteria2CertsForTest exposes removeHysteria2Certs for external tests.
func (s *Service) RemoveHysteria2CertsForTest(vpn *domain.VPN) {
	s.removeHysteria2Certs(vpn)
}

// RemoveTUICCertsForTest exposes removeTUICCerts for external tests.
func (s *Service) RemoveTUICCertsForTest(vpn *domain.VPN) {
	s.removeTUICCerts(vpn)
}

// EnableHTTPTLSForTest exposes enableHTTPTLS for external tests.
func (s *Service) EnableHTTPTLSForTest(vpn *domain.VPN) error {
	return s.enableHTTPTLS(vpn)
}

// DisableHTTPTLSForTest exposes disableHTTPTLS for external tests.
func (s *Service) DisableHTTPTLSForTest(vpn *domain.VPN) {
	s.disableHTTPTLS(vpn)
}

// BuildProtocolDataPreviewForTest exposes buildProtocolDataPreview for external tests.
func (s *Service) BuildProtocolDataPreviewForTest(in CreateVPNInput, tag string) ([]byte, error) {
	return s.buildProtocolDataPreview(in, tag)
}

// BuildProtocolDataForTest exposes buildProtocolData for external tests.
func (s *Service) BuildProtocolDataForTest(in CreateVPNInput, tag string, mode protocol.BuildMode) ([]byte, error) {
	return s.buildProtocolData(in, tag, mode)
}

// ValidateCreateVPNProtocolPreviewForTest exposes validateCreateVPNProtocolPreview for external tests.
func (s *Service) ValidateCreateVPNProtocolPreviewForTest(ctx context.Context, in CreateVPNInput) error {
	return s.validateCreateVPNProtocolPreview(ctx, in)
}

// SetPasswordGenForTest injects password generation for tests.
func (s *Service) SetPasswordGenForTest(g PasswordGen) {
	s.passwordGen = g
}

// SetWireguardKeyGenForTest injects wireguard key generation for tests.
func (s *Service) SetWireguardKeyGenForTest(g WireguardKeyGen) {
	s.wireguardKeyGen = g
}

// SetStoreForTest injects the state store for tests.
func (s *Service) SetStoreForTest(st StateStore) {
	s.store = st
}

// SetRendererForTest injects the config renderer for tests.
func (s *Service) SetRendererForTest(r *render.Renderer) {
	s.renderer = r
}

// WriteInitialConfigForTest exposes writeInitialConfig for external tests.
func (s *Service) WriteInitialConfigForTest(ctx context.Context) error {
	return s.writeInitialConfig(ctx)
}

// SetHTTPMarshalForTest injects HTTP protocol data marshaling for tests.
func (s *Service) SetHTTPMarshalForTest(fn func(httpproxy.ProtocolData) ([]byte, error)) {
	s.httpMarshal = fn
}

// SyncFirewallPortForTest exposes syncFirewallPort for external tests.
func (s *Service) SyncFirewallPortForTest(ctx context.Context, vpn *domain.VPN, oldPort, newPort int) error {
	return s.syncFirewallPort(ctx, vpn, oldPort, newPort)
}

// SetSelfExecutableForTest injects obscura binary path resolution for tests.
func (s *Service) SetSelfExecutableForTest(fn func() (string, error)) {
	s.selfExecutable = fn
}

// SetBackupGlobForTest injects backup archive globbing for tests.
func (s *Service) SetBackupGlobForTest(fn func(pattern string) ([]string, error)) {
	s.backupGlob = fn
}

// SetCongestionListerForTest injects congestion control listing for tests.
func (s *Service) SetCongestionListerForTest(fn func() ([]string, error)) {
	s.congestionLister = fn
}

// SetInstallFnForTest injects sing-box install for bootstrap tests.
func (s *Service) SetInstallFnForTest(fn func(destPath string, onDownload func(read, total int64)) (string, error)) {
	s.installFn = fn
}

// SetLookPathForTest injects exec.LookPath for sing-box binary resolution tests.
func (s *Service) SetLookPathForTest(fn func(string) (string, error)) {
	s.lookPathFn = fn
}

// SetRootCheckForTest injects root privilege check for tests.
func (s *Service) SetRootCheckForTest(fn func() bool) {
	s.rootCheck = fn
}

// SetInstallerForTest injects the sing-box installer for tests.
func (s *Service) SetInstallerForTest(i *install.Installer) {
	s.installer = i
}

// SetSysctlForTest injects the sysctl manager for tests.
func (s *Service) SetSysctlForTest(m *sysctl.Manager) {
	s.sysctl = m
}

// SetSystemdForTest injects the systemd manager for tests.
func (s *Service) SetSystemdForTest(m *systemd.Manager) {
	s.systemd = m
}

// SetSSHDForTest injects sshd configuration helpers for tests.
func (s *Service) SetSSHDForTest(path string, cfg *sshd.Config, run *sshd.Runner) {
	s.sshdPath = path
	s.sshdCfg = cfg
	s.sshdRun = run
}

// SetSSHKeepaliveForTest injects sshd keepalive helpers for tests.
func (s *Service) SetSSHKeepaliveForTest(k *sshd.Keepalive) {
	s.sshKeepaliveMgr = k
}

// SetSSHDInstalledCheckForTest overrides sshd presence detection for tests.
func (s *Service) SetSSHDInstalledCheckForTest(fn func() bool) {
	s.sshdInstalledFn = fn
}

// SetFallbackActiveForTest injects fallback stub active check for tests.
func (s *Service) SetFallbackActiveForTest(fn func(context.Context) (bool, error)) {
	s.fallbackActive = fn
}

// SetFallbackInstallForTest injects fallback stub installation during bootstrap.
func (s *Service) SetFallbackInstallForTest(fn func(context.Context) error) {
	s.fallbackInstall = fn
}

// RollbackConfigForTest exposes rollbackConfig for external tests.
func (s *Service) RollbackConfigForTest(ctx context.Context) error {
	return s.rollbackConfig(ctx)
}

// UninstallFullForTest exposes uninstallFull for external tests.
func (s *Service) UninstallFullForTest(ctx context.Context, wipeData bool) error {
	return s.uninstallFull(ctx, wipeData)
}

// OpenFirewallPortForTest exposes openFirewallPort for external tests.
func (s *Service) OpenFirewallPortForTest(ctx context.Context, port int, protos []string) {
	s.openFirewallPort(ctx, port, protos)
}

// CloseFirewallPortForTest exposes closeFirewallPort for external tests.
func (s *Service) CloseFirewallPortForTest(ctx context.Context, port int, protos []string) {
	s.closeFirewallPort(ctx, port, protos)
}

// SyncSSHFirewallForTest exposes syncSSHFirewall for external tests.
func (s *Service) SyncSSHFirewallForTest(ctx context.Context, oldPort, newPort int) {
	s.syncSSHFirewall(ctx, oldPort, newPort)
}

// SyncSSHPortFromSystemForTest exposes syncSSHPortFromSystem for external tests.
func (s *Service) SyncSSHPortFromSystemForTest() {
	s.syncSSHPortFromSystem()
}

// SingBoxBinaryForTest exposes singBoxBinary for external tests.
func (s *Service) SingBoxBinaryForTest() string {
	return s.singBoxBinary()
}

// GenerateClientPasswordForTest exposes generateClientPassword for external tests.
func (s *Service) GenerateClientPasswordForTest(vpn *domain.VPN) (string, error) {
	return s.generateClientPassword(vpn)
}

// NeedsFallbackStubForTest exposes needsFallbackStub for external tests.
func (s *Service) NeedsFallbackStubForTest(ctx context.Context) bool {
	return s.needsFallbackStub(ctx)
}

// CheckFallbackStubForTest exposes checkFallbackStub for external tests.
func (s *Service) CheckFallbackStubForTest(ctx context.Context) doctor.CheckResult {
	return s.checkFallbackStub(ctx)
}
