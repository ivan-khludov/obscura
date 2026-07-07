// Package runtime wires obscura dependencies for CLI and TUI entrypoints.
package runtime

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/ivan-khludov/obscura/internal/apply"
	"github.com/ivan-khludov/obscura/internal/config"
	"github.com/ivan-khludov/obscura/internal/firewall"
	"github.com/ivan-khludov/obscura/internal/manifest"
	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/service"
	"github.com/ivan-khludov/obscura/internal/singboxcheck"
	"github.com/ivan-khludov/obscura/internal/store"
	"github.com/ivan-khludov/obscura/internal/systemd"
)

// Opener initializes runtime dependencies with optional dependency injection.
type Opener struct {
	MkdirAll     func(path string, perm os.FileMode) error
	OpenStore    func(path string) (*store.Store, error)
	LoadManifest func(m *manifest.Manager) error
	ConfigApp    func(devMode bool) *config.App
	CloseStore   func(st *store.Store) error
	Stderr       io.Writer
}

func (o *Opener) configApp(devMode bool) *config.App {
	if o != nil && o.ConfigApp != nil {
		return o.ConfigApp(devMode)
	}
	if devMode {
		return config.DevApp()
	}
	return config.DefaultApp()
}

func (o *Opener) mkdirAll(path string, perm os.FileMode) error {
	if o != nil && o.MkdirAll != nil {
		return o.MkdirAll(path, perm)
	}
	return os.MkdirAll(path, perm)
}

func (o *Opener) openStore(path string) (*store.Store, error) {
	if o != nil && o.OpenStore != nil {
		return o.OpenStore(path)
	}
	return store.Open(path)
}

func (o *Opener) loadManifest(m *manifest.Manager) error {
	if o != nil && o.LoadManifest != nil {
		return o.LoadManifest(m)
	}
	return m.Load()
}

func (o *Opener) closeStore(st *store.Store) error {
	if o != nil && o.CloseStore != nil {
		return o.CloseStore(st)
	}
	return st.Close()
}

func (o *Opener) stderr() io.Writer {
	if o != nil && o.Stderr != nil {
		return o.Stderr
	}
	return os.Stderr
}

// Open initializes config, store, manifest, and the service layer.
// The returned cleanup function closes the store; callers should defer it.
func Open(devMode bool) (*service.Service, *config.App, func(), error) {
	return (&Opener{}).Open(devMode)
}

// Open initializes runtime dependencies and returns the service layer.
func (o *Opener) Open(devMode bool) (*service.Service, *config.App, func(), error) {
	app := o.configApp(devMode)
	if err := o.mkdirAll(app.DataDir, 0o755); err != nil {
		return nil, nil, nil, fmt.Errorf("mkdir data dir: %w", err)
	}

	st, err := o.openStore(app.DBPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open store: %w", err)
	}
	cleanup := func() {
		if err := o.closeStore(st); err != nil {
			_, _ = fmt.Fprintf(o.stderr(), "close store: %v\n", err)
		}
	}

	man := manifest.NewManager(app.ManifestPath)
	if err := o.loadManifest(man); err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("load manifest: %w", err)
	}

	reg := NewProtocolRegistry()
	var checker apply.SingBoxChecker = singboxcheck.NewChecker(singboxcheck.DefaultBinaryPath)
	var systemdMgr apply.ServiceManager = systemd.NewManager()
	var fw service.FirewallManager = firewall.NewUfw()
	if devMode {
		checker = singboxcheck.NopChecker{}
		systemdMgr = systemd.NopManager{}
		fw = firewall.NopFirewall{}
	}

	svc := service.NewService(app, st, reg, man, fw, checker, systemdMgr)
	return svc, app, cleanup, nil
}

// OpenWithOrchestration initializes runtime dependencies and returns orchestration facade.
func OpenWithOrchestration(devMode bool) (*orchestration.Facade, *config.App, func(), error) {
	return (&Opener{}).OpenWithOrchestration(devMode)
}

// OpenWithOrchestration initializes runtime dependencies and returns orchestration facade.
func (o *Opener) OpenWithOrchestration(devMode bool) (*orchestration.Facade, *config.App, func(), error) {
	svc, app, cleanup, err := o.Open(devMode)
	if err != nil {
		return nil, nil, nil, err
	}
	return orchestration.New(svc), app, cleanup, nil
}

// ShouldRunTUI reports whether args select the root command with no subcommand.
func ShouldRunTUI(root *cobra.Command, args []string) bool {
	if root == nil {
		return len(args) == 0
	}
	cmd, _, err := root.Find(args)
	if err != nil {
		return false
	}
	return cmd == root
}
