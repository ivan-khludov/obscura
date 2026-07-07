package apply

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ivan-khludov/obscura/internal/render"
	"github.com/ivan-khludov/obscura/internal/store"
)

// SingBoxChecker validates sing-box configuration files.
type SingBoxChecker interface {
	Check(ctx context.Context, configPath string) error
}

// ServiceManager reloads or restarts the sing-box systemd unit.
type ServiceManager interface {
	Reload(ctx context.Context) error
	IsActive(ctx context.Context) (bool, error)
}

type renderSource interface {
	Render(ctx context.Context) ([]byte, error)
}

// Pipeline applies rendered sing-box configuration to disk and reloads the service.
type Pipeline struct {
	renderer   renderSource
	store      *store.Store
	checker    SingBoxChecker
	systemd    ServiceManager
	configPath string
}

// Options configures the apply pipeline.
type Options struct {
	ConfigPath string
}

// NewPipeline returns a Pipeline with the given dependencies.
func NewPipeline(renderer renderSource, s *store.Store, checker SingBoxChecker, systemd ServiceManager, opts Options) *Pipeline {
	path := opts.ConfigPath
	if path == "" {
		path = render.DefaultConfigPath
	}
	return &Pipeline{
		renderer:   renderer,
		store:      s,
		checker:    checker,
		systemd:    systemd,
		configPath: path,
	}
}

// Result describes the outcome of an apply operation.
type Result struct {
	ConfigPath string
	DryRun     bool
	Bytes      []byte
}

// Apply renders, validates, writes, saves a revision, and reloads sing-box.
func (p *Pipeline) Apply(ctx context.Context, dryRun bool) (*Result, error) {
	data, err := p.renderer.Render(ctx)
	if err != nil {
		return nil, fmt.Errorf("render: %w", err)
	}
	if len(data) == 0 || data[0] != '{' {
		return nil, fmt.Errorf("render produced empty config")
	}
	tmpPath := p.configPath + ".tmp"
	if err := os.MkdirAll(filepath.Dir(p.configPath), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir config dir: %w", err)
	}
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return nil, fmt.Errorf("write temp config: %w", err)
	}
	if p.checker != nil {
		if err := p.checker.Check(ctx, tmpPath); err != nil {
			_ = os.Remove(tmpPath)
			return nil, fmt.Errorf("sing-box check: %w", err)
		}
	}
	if dryRun {
		_ = os.Remove(tmpPath)
		return &Result{ConfigPath: p.configPath, DryRun: true, Bytes: data}, nil
	}
	if err := os.Rename(tmpPath, p.configPath); err != nil {
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("commit config: %w", err)
	}
	if _, err := p.store.SaveRevision(ctx, data); err != nil {
		return nil, fmt.Errorf("save revision: %w", err)
	}
	if p.systemd != nil {
		if err := p.systemd.Reload(ctx); err != nil {
			return nil, fmt.Errorf("reload sing-box: %w", err)
		}
	}
	return &Result{ConfigPath: p.configPath, DryRun: false, Bytes: data}, nil
}

// Rollback restores the previous config revision and reloads sing-box.
func (p *Pipeline) Rollback(ctx context.Context) error {
	data, _, err := p.store.PreviousRevision(ctx)
	if err != nil {
		return fmt.Errorf("previous revision: %w", err)
	}
	tmpPath := p.configPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("write rollback temp: %w", err)
	}
	if p.checker != nil {
		if err := p.checker.Check(ctx, tmpPath); err != nil {
			_ = os.Remove(tmpPath)
			return fmt.Errorf("sing-box check rollback: %w", err)
		}
	}
	if err := os.Rename(tmpPath, p.configPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("commit rollback: %w", err)
	}
	if _, err := p.store.SaveRevision(ctx, data); err != nil {
		return fmt.Errorf("save rollback revision: %w", err)
	}
	if p.systemd != nil {
		return p.systemd.Reload(ctx)
	}
	return nil
}
