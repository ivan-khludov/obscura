// Package version holds the obscura release version (single source of truth).
package version

// Version is the current obscura release. Override at link time with:
//
//	go build -ldflags "-X github.com/ivan-khludov/obscura/internal/version.Version=0.0.2" ./cmd/obscura
//
// or: make build VERSION=0.0.2
var Version = "0.0.1"

// Release returns the current obscura release version.
func Release() string {
	return Version
}
