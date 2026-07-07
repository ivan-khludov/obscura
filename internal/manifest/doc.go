// Package manifest tracks resources provisioned by Obscura so they can be removed on uninstall.
// Each resource type (file, sysctl entry, firewall rule) is recorded in a JSON manifest file.
// The manifest is loaded at startup and updated atomically after each provisioning step.
package manifest
