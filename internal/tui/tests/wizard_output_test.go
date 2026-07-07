package tui_test

import (
	"github.com/ivan-khludov/obscura/internal/tui"
	"strings"
	"testing"
)

func TestFormatURIWithQRForTest(t *testing.T) {
	out, err := tui.FormatURIWithQRForTest("ss://example")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ss://example") {
		t.Fatalf("expected uri in output, got %q", out)
	}
}

func TestFormatClientExportForTest(t *testing.T) {
	out, err := tui.FormatClientExportForTest("ss://example", "ss://example")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ss://example") {
		t.Fatalf("expected uri in output, got %q", out)
	}
}

func TestFormatClientExportForTestDifferentQRContent(t *testing.T) {
	out, err := tui.FormatClientExportForTest("ss://example", "qr-content")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ss://example") {
		t.Fatalf("expected uri in output, got %q", out)
	}
}
