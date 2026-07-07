package cmd_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/version"
)

func TestVersionJSON(t *testing.T) {
	root, ctx := newTestRoot(t)
	out := runJSONCommand(t, root, ctx, "version", "--json")
	var result struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if result.Version == "" {
		t.Fatal("expected non-empty version")
	}
	if result.Version != version.Version {
		t.Fatalf("expected version %q, got %q", version.Version, result.Version)
	}
}

func TestVersionText(t *testing.T) {
	root, ctx := newTestRoot(t)
	out, err := runCommand(t, root, ctx, "version")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) != version.Version {
		t.Fatalf("expected version text %q, got %q", version.Version, out)
	}
}
