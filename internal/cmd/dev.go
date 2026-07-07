package cmd

import "strings"

// ParseDevFlag reports whether --dev appears anywhere in args.
func ParseDevFlag(args []string) bool {
	for _, arg := range args {
		switch {
		case arg == "--dev":
			return true
		case strings.HasPrefix(arg, "--dev="):
			val := strings.TrimPrefix(arg, "--dev=")
			return val == "true" || val == "1"
		}
	}
	return false
}
