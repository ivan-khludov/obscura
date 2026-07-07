// Package service implements obscura use-cases over store, render, and system adapters.
package service

import (
	"context"
	"path/filepath"

	"github.com/ivan-khludov/obscura/internal/apply"
	"github.com/ivan-khludov/obscura/internal/config"
	"github.com/ivan-khludov/obscura/internal/install"
	"github.com/ivan-khludov/obscura/internal/manifest"
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/protocol/httpproxy"
	"github.com/ivan-khludov/obscura/internal/render"
	"github.com/ivan-khludov/obscura/internal/sshd"
	"github.com/ivan-khludov/obscura/internal/store"
	"github.com/ivan-khludov/obscura/internal/sysctl"
	"github.com/ivan-khludov/obscura/internal/systemd"
)

// FirewallManager opens and closes firewall rules for VPN ports.
type FirewallManager interface {
	AllowPort(ctx context.Context, port int, proto string) (string, error)
	DeleteRule(ctx context.Context, spec string) error
	IsAvailable() bool
	Enable(ctx context.Context, sshPort int) error
}

// Service coordinates VPN, client, bootstrap, and apply operations.
type Service struct {
	app              *config.App
	store            StateStore
	storeDB          *store.Store
	registry         *protocol.Registry
	renderer         *render.Renderer
	pipeline         *apply.Pipeline
	manifest         *manifest.Manager
	sysctl           *sysctl.Manager
	systemd          *systemd.Manager
	systemdMgr       apply.ServiceManager
	checker          apply.SingBoxChecker
	firewall         FirewallManager
	installer        *install.Installer
	passwordGen      PasswordGen
	wireguardKeyGen  WireguardKeyGen
	lookPathFn       func(string) (string, error)
	installFn        func(destPath string, onDownload func(read, total int64)) (string, error)
	congestionLister func() ([]string, error)
	rootCheck        func() bool
	sshdPath         string
	sshdCfg          *sshd.Config
	sshdRun          *sshd.Runner
	sshKeepaliveMgr  *sshd.Keepalive
	sshdInstalledFn  func() bool
	fallbackActive   func(ctx context.Context) (bool, error)
	fallbackInstall  func(ctx context.Context) error
	httpMarshal      func(httpproxy.ProtocolData) ([]byte, error)
	backupGlob       func(pattern string) ([]string, error)
	selfExecutable   func() (string, error)

	VPNs         *VPNService
	Clients      *ClientService
	System       *SystemService
	Bootstrapper *BootstrapService
	Maintenance  *MaintenanceService
}

// NewService wires dependencies for obscura use-cases.
func NewService(app *config.App, s *store.Store, reg *protocol.Registry, man *manifest.Manager, fw FirewallManager, checker apply.SingBoxChecker, systemdMgr apply.ServiceManager) *Service {
	renderer := render.NewRenderer(s, reg)
	pipeline := apply.NewPipeline(renderer, s, checker, systemdMgr, apply.Options{ConfigPath: app.ConfigPath})
	svc := &Service{
		app:        app,
		store:      s,
		storeDB:    s,
		registry:   reg,
		renderer:   renderer,
		pipeline:   pipeline,
		manifest:   man,
		sysctl:     sysctl.NewManager(),
		systemd:    systemd.NewManager(),
		systemdMgr: systemdMgr,
		checker:    checker,
		firewall:   fw,
		installer:  install.NewInstaller(filepath.Join(app.DataDir, "cache")),
	}
	svc.VPNs, svc.Clients, svc.System, svc.Bootstrapper, svc.Maintenance = newUseCases(svc)
	return svc
}

// ListProtocols returns registered protocol type names in display order.
func (s *Service) ListProtocols() []string {
	return s.registry.List()
}
