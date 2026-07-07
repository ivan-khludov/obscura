// Package fallback installs and manages the local HTTP stub for TLS inbound fallback.
package fallback

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
)

//go:embed assets/Caddyfile assets/site/index.html assets/obscura-fallback.service
var assetsFS embed.FS

// DefaultServer is the fallback stub listen address host.
const DefaultServer = "127.0.0.1"

// DefaultPort is the fallback stub listen port.
const DefaultPort = 8080

// UnitName is the systemd unit for the fallback stub.
const UnitName = "obscura-fallback.service"

// UnitPath is the systemd unit file location.
const UnitPath = "/etc/systemd/system/obscura-fallback.service"

// InstallDir is where fallback assets are deployed on the server.
const InstallDir = "/etc/obscura/fallback"

// Installer deploys fallback stub assets and optionally starts the systemd unit.
type Installer struct {
	DevMode      bool
	DataDir      string
	MkdirAll     func(path string, perm os.FileMode) error
	WriteFile    func(name string, data []byte, perm os.FileMode) error
	LookPath     func(file string) (string, error)
	RunCommand   func(ctx context.Context, name string, args ...string) ([]byte, error)
	ReadEmbedded func(name string) ([]byte, error)
}

// ActiveChecker reports fallback systemd unit status.
type ActiveChecker struct {
	RunCommand func(ctx context.Context, name string, args ...string) ([]byte, error)
}

func (i *Installer) mkdirAll(path string, perm os.FileMode) error {
	if i.MkdirAll != nil {
		return i.MkdirAll(path, perm)
	}
	return os.MkdirAll(path, perm)
}

func (i *Installer) writeFile(name string, data []byte, perm os.FileMode) error {
	if i.WriteFile != nil {
		return i.WriteFile(name, data, perm)
	}
	return os.WriteFile(name, data, perm)
}

func (i *Installer) lookPath(file string) (string, error) {
	if i.LookPath != nil {
		return i.LookPath(file)
	}
	return exec.LookPath(file)
}

func (i *Installer) runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	if i.RunCommand != nil {
		return i.RunCommand(ctx, name, args...)
	}
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func (i *Installer) readEmbedded(name string) ([]byte, error) {
	if i.ReadEmbedded != nil {
		return i.ReadEmbedded(name)
	}
	return assetsFS.ReadFile(name)
}

func (c *ActiveChecker) runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	if c != nil && c.RunCommand != nil {
		return c.RunCommand(ctx, name, args...)
	}
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// installDir performs an internal helper operation.
func (i *Installer) installDir() string {
	if i.DevMode && i.DataDir != "" {
		return filepath.Join(i.DataDir, "fallback")
	}
	return InstallDir
}

// Install copies stub site assets and installs the systemd unit.
func (i *Installer) Install(ctx context.Context) error {
	if err := i.deployAssets(); err != nil {
		return err
	}
	if i.DevMode {
		return nil
	}
	if err := i.ensureCaddy(); err != nil {
		return err
	}
	if err := i.installUnit(ctx); err != nil {
		return err
	}
	return i.start(ctx)
}

// IsActive reports whether the fallback systemd unit is running.
func IsActive(ctx context.Context) (bool, error) {
	return (&ActiveChecker{}).IsActive(ctx)
}

// IsActive reports whether the fallback systemd unit is running.
func (c *ActiveChecker) IsActive(ctx context.Context) (bool, error) {
	out, err := c.runCommand(ctx, "systemctl", "is-active", UnitName)
	if err != nil {
		if len(out) == 0 {
			return false, nil
		}
		return false, nil
	}
	return string(out) == "active\n", nil
}

// deployAssets performs an internal helper operation.
func (i *Installer) deployAssets() error {
	dir := i.installDir()
	siteDir := filepath.Join(dir, "site")
	if err := i.mkdirAll(siteDir, 0o755); err != nil {
		return fmt.Errorf("mkdir fallback: %w", err)
	}
	caddyfile := fmt.Sprintf("%s:8080 {\n\troot * %s\n\tfile_server\n}\n", DefaultServer, siteDir)
	if err := i.writeFile(filepath.Join(dir, "Caddyfile"), []byte(caddyfile), 0o644); err != nil {
		return fmt.Errorf("write caddyfile: %w", err)
	}
	if err := i.copyEmbedded("assets/site/index.html", filepath.Join(siteDir, "index.html"), 0o644); err != nil {
		return err
	}
	if i.DevMode {
		return nil
	}
	if err := i.mkdirAll(filepath.Dir(UnitPath), 0o755); err != nil {
		return fmt.Errorf("mkdir systemd: %w", err)
	}
	return i.copyEmbedded("assets/obscura-fallback.service", UnitPath, 0o644)
}

// copyEmbedded performs an internal helper operation.
func (i *Installer) copyEmbedded(name, dest string, mode fs.FileMode) error {
	raw, err := i.readEmbedded(name)
	if err != nil {
		return fmt.Errorf("read embedded %s: %w", name, err)
	}
	if err := i.mkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(dest), err)
	}
	if err := i.writeFile(dest, raw, mode); err != nil {
		return fmt.Errorf("write %s: %w", dest, err)
	}
	return nil
}

// ensureCaddy performs an internal helper operation.
func (i *Installer) ensureCaddy() error {
	if _, err := i.lookPath("caddy"); err == nil {
		return nil
	}
	if _, err := i.lookPath("apt-get"); err != nil {
		return fmt.Errorf("caddy not found and apt-get unavailable; install caddy manually")
	}
	out, err := i.runCommand(context.Background(), "apt-get", "update")
	if err != nil {
		return fmt.Errorf("apt-get update: %w: %s", err, out)
	}
	out, err = i.runCommand(context.Background(), "apt-get", "install", "-y", "caddy")
	if err != nil {
		return fmt.Errorf("install caddy: %w: %s", err, out)
	}
	return nil
}

// installUnit performs an internal helper operation.
func (i *Installer) installUnit(ctx context.Context) error {
	if err := i.run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	return i.run(ctx, "systemctl", "enable", UnitName)
}

// start starts a wizard or async operation.
func (i *Installer) start(ctx context.Context) error {
	return i.run(ctx, "systemctl", "start", UnitName)
}

// run runs CLI or installation logic.
func (i *Installer) run(ctx context.Context, name string, args ...string) error {
	out, err := i.runCommand(ctx, name, args...)
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, out)
	}
	return nil
}
