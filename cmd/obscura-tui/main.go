// Package main is the obscura TUI entrypoint without cobra subcommands.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/ivan-khludov/obscura/internal/cmd"
	"github.com/ivan-khludov/obscura/internal/runtime"
	"github.com/ivan-khludov/obscura/internal/tui"
)

func main() {
	devMode := cmd.ParseDevFlag(os.Args[1:])
	if !tui.IsTTY(os.Stdin) || !tui.IsTTY(os.Stdout) {
		fmt.Fprintln(os.Stderr, "obscura-tui requires an interactive terminal")
		os.Exit(1)
	}

	orch, app, cleanup, err := runtime.OpenWithOrchestration(devMode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	defer cleanup()

	if err := tui.Run(context.Background(), orch, app); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
