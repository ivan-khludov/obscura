// Package singboxcheck wraps sing-box config validation via external binary.
package singboxcheck

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// DefaultBinaryPath is the default sing-box executable location.
const DefaultBinaryPath = "/usr/local/bin/sing-box"

// Checker runs sing-box check against configuration files.
type Checker struct {
	BinaryPath string
	Stat       func(name string) (os.FileInfo, error)
	RunCommand func(ctx context.Context, name string, args ...string) ([]byte, error)
}

// NewChecker returns a Checker using the given sing-box binary path.
func NewChecker(binaryPath string) *Checker {
	if binaryPath == "" {
		binaryPath = DefaultBinaryPath
	}
	return &Checker{BinaryPath: binaryPath}
}

func (c *Checker) stat(name string) (os.FileInfo, error) {
	if c.Stat != nil {
		return c.Stat(name)
	}
	return os.Stat(name)
}

func (c *Checker) runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	if c.RunCommand != nil {
		return c.RunCommand(ctx, name, args...)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

// Check validates configPath using sing-box check.
func (c *Checker) Check(ctx context.Context, configPath string) error {
	if _, err := c.stat(c.BinaryPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("sing-box not installed — run Bootstrap server first (or use --dev for local testing)")
		}
		return fmt.Errorf("sing-box binary %s: %w", c.BinaryPath, err)
	}
	out, err := c.runCommand(ctx, c.BinaryPath, "check", "-c", configPath)
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("%w: %s", err, msg)
		}
		return err
	}
	return nil
}

// NopChecker skips sing-box validation when binary is unavailable.
type NopChecker struct{}

// Check is a no-op validation used in tests or before bootstrap.
func (NopChecker) Check(_ context.Context, _ string) error {
	return nil
}
