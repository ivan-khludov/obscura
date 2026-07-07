// Package firewall manages ufw rules added by obscura.
package firewall

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Ufw applies and removes ufw firewall rules.
type Ufw struct {
	RunCommand func(ctx context.Context, name string, args ...string) ([]byte, error)
	LookPath   func(file string) (string, error)
}

func (u *Ufw) runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	if u != nil && u.RunCommand != nil {
		return u.RunCommand(ctx, name, args...)
	}
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func (u *Ufw) lookPath(file string) (string, error) {
	if u != nil && u.LookPath != nil {
		return u.LookPath(file)
	}
	return exec.LookPath(file)
}

// NewUfw returns a Ufw manager.
func NewUfw() *Ufw {
	return &Ufw{}
}

// AllowPort adds a ufw allow rule for proto/port.
func (u *Ufw) AllowPort(ctx context.Context, port int, proto string) (string, error) {
	spec := fmt.Sprintf("%d/%s", port, proto)
	out, err := u.runCommand(ctx, "ufw", "allow", spec)
	if err != nil {
		return "", fmt.Errorf("ufw allow %s: %s: %s", spec, err, string(out))
	}
	return spec, nil
}

// DeleteRule removes a ufw rule matching spec.
func (u *Ufw) DeleteRule(ctx context.Context, spec string) error {
	out, err := u.runCommand(ctx, "ufw", "delete", "allow", spec)
	if err != nil {
		text := string(out)
		if strings.Contains(text, "Could not delete") {
			return nil
		}
		return fmt.Errorf("ufw delete allow %s: %s: %s", spec, err, text)
	}
	return nil
}

// Enable allows SSH and activates ufw.
func (u *Ufw) Enable(ctx context.Context, sshPort int) error {
	if _, err := u.AllowPort(ctx, sshPort, "tcp"); err != nil {
		return fmt.Errorf("ufw allow ssh: %w", err)
	}
	out, err := u.runCommand(ctx, "ufw", "--force", "enable")
	if err != nil {
		return fmt.Errorf("ufw enable: %s: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// IsAvailable reports whether ufw is installed.
func (u *Ufw) IsAvailable() bool {
	_, err := u.lookPath("ufw")
	return err == nil
}

// NopFirewall skips firewall operations in dev mode.
type NopFirewall struct{}

// AllowPort returns a synthetic rule spec without applying it.
func (NopFirewall) AllowPort(_ context.Context, port int, proto string) (string, error) {
	return fmt.Sprintf("%d/%s", port, proto), nil
}

// DeleteRule is a no-op delete.
func (NopFirewall) DeleteRule(_ context.Context, _ string) error { return nil }

// Enable is a no-op enable.
func (NopFirewall) Enable(_ context.Context, _ int) error { return nil }

// IsAvailable always returns false.
func (NopFirewall) IsAvailable() bool { return false }
