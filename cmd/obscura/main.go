// Package main is the universal obscura binary: TUI on a TTY with no subcommand, otherwise CLI.
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
	orch, app, cleanup, err := runtime.OpenWithOrchestration(devMode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	defer cleanup()

	root := cmd.NewRootCommand(orch, app, &devMode, cmd.Options{})
	args := os.Args[1:]
	if runtime.ShouldRunTUI(root, args) && tui.IsTTY(os.Stdin) && tui.IsTTY(os.Stdout) {
		if err := tui.Run(context.Background(), orch, app); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
