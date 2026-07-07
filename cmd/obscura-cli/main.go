// Package main is the obscura CLI entrypoint without TUI.
package main

import (
	"fmt"
	"os"

	"github.com/ivan-khludov/obscura/internal/cmd"
	"github.com/ivan-khludov/obscura/internal/runtime"
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
	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
