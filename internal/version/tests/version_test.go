package version_test

import (
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/version"
)

func TestVersionNonEmpty(t *testing.T) {
	if strings.TrimSpace(version.Version) == "" {
		t.Fatal("version.Version must not be empty")
	}
}

func TestRelease(t *testing.T) {
	if version.Release() != version.Version {
		t.Fatalf("Release() = %q, Version = %q", version.Release(), version.Version)
	}
	if strings.TrimSpace(version.Release()) == "" {
		t.Fatal("version.Release() must not be empty")
	}
}
