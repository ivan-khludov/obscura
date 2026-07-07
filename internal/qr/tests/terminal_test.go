package qr_test

import (
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/qr"
)

func TestTerminal_OK(t *testing.T) {
	content := "socks5://user:pass@127.0.0.1:1080"
	ascii, err := qr.Terminal(content)
	if err != nil {
		t.Fatalf("Terminal: %v", err)
	}
	if ascii == "" {
		t.Fatal("expected non-empty qr output")
	}
	if strings.HasSuffix(ascii, "\n") {
		t.Fatal("expected trailing newline trimmed")
	}
	if !strings.Contains(ascii, "█") && !strings.Contains(ascii, "▄") {
		t.Fatalf("expected qr blocks in output, got %q", ascii)
	}
}

func TestTerminal_Error(t *testing.T) {
	_, err := qr.Terminal("")
	if err == nil {
		t.Fatal("expected error for empty content")
	}

	_, err = qr.Terminal(strings.Repeat("a", 5000))
	if err == nil {
		t.Fatal("expected error for content too long to encode")
	}
}
