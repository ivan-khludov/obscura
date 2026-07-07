// Package orchestration provides a request/response facade over the service layer
// for use by CLI commands and the TUI. It normalises input from external
// representations (flags, wizard state) into service inputs, applies
// cross-cutting guards, and exposes strongly-typed view types to callers.
// Business logic lives in service; orchestration owns request mapping and pipeline coordination.
package orchestration
