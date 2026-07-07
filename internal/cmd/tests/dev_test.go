package cmd_test

import (
	"testing"

	"github.com/ivan-khludov/obscura/internal/cmd"
)

func TestParseDevFlag(t *testing.T) {
	if !cmd.ParseDevFlag([]string{"--dev", "bootstrap"}) {
		t.Fatal("expected --dev before subcommand")
	}
	if !cmd.ParseDevFlag([]string{"vpn", "create", "--dev"}) {
		t.Fatal("expected --dev after subcommand")
	}
	if cmd.ParseDevFlag([]string{"vpn", "create"}) {
		t.Fatal("unexpected --dev")
	}
	if cmd.ParseDevFlag([]string{"--dev=false", "bootstrap"}) {
		t.Fatal("unexpected --dev=false")
	}
	if !cmd.ParseDevFlag([]string{"--dev=true", "bootstrap"}) {
		t.Fatal("expected --dev=true")
	}
	if !cmd.ParseDevFlag([]string{"--dev=1", "bootstrap"}) {
		t.Fatal("expected --dev=1")
	}
}
