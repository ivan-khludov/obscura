// Package platform provides OS-level helpers for obscura.
package platform

import "os"

// IsRoot reports whether the current process has root privileges.
func IsRoot() bool {
	return os.Geteuid() == 0
}
