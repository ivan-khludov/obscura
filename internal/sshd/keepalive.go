package sshd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

const (
	// KeepaliveConfPath is the sshd drop-in written by obscura bootstrap.
	KeepaliveConfPath = "/etc/ssh/sshd_config.d/99-obscura.conf"
	// DefaultClientAliveInterval is the server-side SSH keepalive interval in seconds.
	DefaultClientAliveInterval = 15
	// DefaultClientAliveCountMax is missed keepalives before sshd closes the session.
	DefaultClientAliveCountMax = 6
)

// Keepalive manages the obscura sshd keepalive drop-in.
type Keepalive struct {
	ConfPath   string
	Interval   int
	CountMax   int
	Config     *Config
	Runner     *Runner
	MkdirAll   func(path string, perm os.FileMode) error
	RemoveFile func(name string) error
}

// NewKeepalive returns a Keepalive with default paths and intervals.
func NewKeepalive() *Keepalive {
	return &Keepalive{
		ConfPath: KeepaliveConfPath,
		Interval: DefaultClientAliveInterval,
		CountMax: DefaultClientAliveCountMax,
		Config:   new(Config),
		Runner:   new(Runner),
	}
}

func (k *Keepalive) confPath() string {
	if k != nil && k.ConfPath != "" {
		return k.ConfPath
	}
	return KeepaliveConfPath
}

func (k *Keepalive) interval() int {
	if k != nil && k.Interval > 0 {
		return k.Interval
	}
	return DefaultClientAliveInterval
}

func (k *Keepalive) countMax() int {
	if k != nil && k.CountMax > 0 {
		return k.CountMax
	}
	return DefaultClientAliveCountMax
}

func (k *Keepalive) config() *Config {
	if k != nil && k.Config != nil {
		return k.Config
	}
	return new(Config)
}

func (k *Keepalive) runner() *Runner {
	if k != nil && k.Runner != nil {
		return k.Runner
	}
	return new(Runner)
}

func (k *Keepalive) mkdirAll(path string, perm os.FileMode) error {
	if k != nil && k.MkdirAll != nil {
		return k.MkdirAll(path, perm)
	}
	return os.MkdirAll(path, perm)
}

func (k *Keepalive) removeFile(name string) error {
	if k != nil && k.RemoveFile != nil {
		return k.RemoveFile(name)
	}
	return os.Remove(name)
}

// Content returns the sshd drop-in body for keepalive settings.
func (k *Keepalive) Content() string {
	return fmt.Sprintf("ClientAliveInterval %d\nClientAliveCountMax %d\n", k.interval(), k.countMax())
}

// Install writes the drop-in, validates sshd config, and reloads ssh.
func (k *Keepalive) Install(ctx context.Context) error {
	path := k.confPath()
	if err := k.mkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir sshd_config.d: %w", err)
	}
	cfg := k.config()
	if err := cfg.writeFile(path, []byte(k.Content()), 0o644); err != nil {
		return fmt.Errorf("write ssh keepalive conf: %w", err)
	}
	if err := k.runner().TestConfig(ctx, ConfigPath); err != nil {
		_ = k.removeFile(path)
		return fmt.Errorf("sshd test after keepalive install: %w", err)
	}
	if err := k.runner().Reload(ctx); err != nil {
		_ = k.removeFile(path)
		return fmt.Errorf("reload ssh after keepalive install: %w", err)
	}
	return nil
}

// Remove deletes the drop-in and reloads ssh when the file was present.
func (k *Keepalive) Remove(ctx context.Context) error {
	path := k.confPath()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("stat ssh keepalive conf: %w", err)
	}
	if err := k.removeFile(path); err != nil {
		return fmt.Errorf("remove ssh keepalive conf: %w", err)
	}
	return k.runner().Reload(ctx)
}
