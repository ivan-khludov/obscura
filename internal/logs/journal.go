// Package logs reads sing-box service logs via journalctl.
package logs

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// DefaultUnitName is the systemd unit used for sing-box logs.
const DefaultUnitName = "sing-box.service"

// Reader fetches sing-box journal logs.
type Reader struct {
	UnitName   string
	RunCommand func(ctx context.Context, name string, args []string, stdout, stderr io.Writer) error
}

func (r *Reader) runCommand(ctx context.Context, name string, args []string, stdout, stderr io.Writer) error {
	if r != nil && r.RunCommand != nil {
		return r.RunCommand(ctx, name, args, stdout, stderr)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

// NewReader returns a Reader for the sing-box systemd unit.
func NewReader() *Reader {
	return &Reader{UnitName: DefaultUnitName}
}

// Print writes recent sing-box logs to w.
func (r *Reader) Print(ctx context.Context, w io.Writer, follow bool, since string) error {
	args := []string{"-u", r.UnitName, "--no-pager", "-o", "cat"}
	if since != "" {
		args = append(args, "--since", since)
	}
	if follow {
		args = append(args, "-f")
	}
	if err := r.runCommand(ctx, "journalctl", args, w, w); err != nil {
		if strings.Contains(err.Error(), "exit status") {
			return nil
		}
		return fmt.Errorf("journalctl: %w", err)
	}
	return nil
}
