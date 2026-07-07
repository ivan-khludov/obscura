//go:build linux

package platform_test

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/platform"
)

func writeProcNetFile(t *testing.T, name string, lines ...string) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

type closeErrFile struct {
	*os.File
	closeErr error
}

func (f *closeErrFile) Close() error {
	if f.closeErr != nil {
		return f.closeErr
	}
	return f.File.Close()
}

type errReadCloser struct {
	headerDone bool
	readErr    error
}

func (e *errReadCloser) Read(p []byte) (int, error) {
	if !e.headerDone {
		e.headerDone = true
		line := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
		return copy(p, line), nil
	}
	return 0, e.readErr
}

func (e *errReadCloser) Close() error { return nil }

func TestLocalPortBound_TCPFromProc(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port

	bound, err := platform.LocalPortBound("tcp", port)
	if err != nil {
		t.Fatal(err)
	}
	if !bound {
		t.Fatalf("expected tcp/%d bound", port)
	}
}

func TestLocalPortBound_TCPFreePort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	bound, err := platform.LocalPortBound("tcp", port)
	if err != nil {
		t.Fatal(err)
	}
	if bound {
		t.Fatalf("expected tcp/%d free", port)
	}
}

func TestLocalPortBound_ProcNetParsing(t *testing.T) {
	t.Run("tcp listen state", func(t *testing.T) {
		port := 8080
		line := fmt.Sprintf("   0: 0100007F:%04X 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 123 1 00000000 100 0 0 10 0", port)
		f := writeProcNetFile(t, "tcp", "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode", line)
		checker := platform.PortChecker{
			OpenFile: func(string) (io.ReadCloser, error) { return f, nil },
		}
		bound, err := checker.LocalPortBound("tcp", port)
		if err != nil {
			t.Fatal(err)
		}
		if !bound {
			t.Fatal("expected bound from proc")
		}
	})

	t.Run("tcp non-listen state skipped", func(t *testing.T) {
		port := 8081
		line := fmt.Sprintf("   0: 0100007F:%04X 00000000:0000 06 00000000:00000000 00:00000000 00000000     0        0 123 1 00000000 100 0 0 10 0", port)
		f := writeProcNetFile(t, "tcp2", "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode", line)
		checker := platform.PortChecker{
			OpenFile: func(string) (io.ReadCloser, error) { return f, nil },
		}
		bound, err := checker.LocalPortBound("tcp", port)
		if err != nil {
			t.Fatal(err)
		}
		if bound {
			t.Fatal("expected not bound for non-listen state")
		}
	})

	t.Run("udp entry", func(t *testing.T) {
		port := 5353
		line := fmt.Sprintf("   0: 00000000:%04X 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 123 1 00000000 100 0 0 10 0", port)
		f := writeProcNetFile(t, "udp", "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode", line)
		checker := platform.PortChecker{
			OpenFile: func(string) (io.ReadCloser, error) { return f, nil },
		}
		bound, err := checker.LocalPortBound("udp", port)
		if err != nil {
			t.Fatal(err)
		}
		if !bound {
			t.Fatal("expected udp bound from proc")
		}
	})

	t.Run("invalid local address skipped", func(t *testing.T) {
		f := writeProcNetFile(t, "bad", "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
			"   0: invalid 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 123 1 00000000 100 0 0 10 0",
			"   0: 0100007F:ZZZZ 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 123 1 00000000 100 0 0 10 0",
		)
		checker := platform.PortChecker{
			OpenFile: func(string) (io.ReadCloser, error) { return f, nil },
		}
		bound, err := checker.LocalPortBound("tcp", 8080)
		if err != nil {
			t.Fatal(err)
		}
		if bound {
			t.Fatal("expected not bound")
		}
	})

	t.Run("short line skipped", func(t *testing.T) {
		f := writeProcNetFile(t, "short", "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
			"incomplete line",
		)
		checker := platform.PortChecker{
			OpenFile: func(string) (io.ReadCloser, error) { return f, nil },
		}
		bound, err := checker.LocalPortBound("tcp", 8080)
		if err != nil {
			t.Fatal(err)
		}
		if bound {
			t.Fatal("expected not bound")
		}
	})

	t.Run("empty body after header", func(t *testing.T) {
		f := writeProcNetFile(t, "empty", "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode")
		checker := platform.PortChecker{
			OpenFile: func(string) (io.ReadCloser, error) { return f, nil },
		}
		bound, err := checker.LocalPortBound("tcp", 8080)
		if err != nil {
			t.Fatal(err)
		}
		if bound {
			t.Fatal("expected not bound")
		}
	})

	t.Run("empty file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "emptyfile")
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		checker := platform.PortChecker{
			OpenFile: func(string) (io.ReadCloser, error) { return f, nil },
		}
		bound, err := checker.LocalPortBound("tcp", 8080)
		if err != nil {
			t.Fatal(err)
		}
		if bound {
			t.Fatal("expected not bound")
		}
	})

	t.Run("scanner read error", func(t *testing.T) {
		checker := platform.PortChecker{
			OpenFile: func(string) (io.ReadCloser, error) {
				return &errReadCloser{readErr: errors.New("read failed")}, nil
			},
		}
		_, err := checker.LocalPortBound("tcp", 8080)
		if err == nil || !strings.Contains(err.Error(), "read failed") {
			t.Fatalf("expected read error, got %v", err)
		}
	})

	t.Run("close error propagated", func(t *testing.T) {
		port := 8082
		line := fmt.Sprintf("   0: 0100007F:%04X 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 123 1 00000000 100 0 0 10 0", port)
		raw := writeProcNetFile(t, "close", "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode", line)
		wrapped := &closeErrFile{File: raw, closeErr: errors.New("close failed")}
		checker := platform.PortChecker{
			OpenFile: func(string) (io.ReadCloser, error) { return wrapped, nil },
		}
		_, err := checker.LocalPortBound("tcp", port)
		if err == nil || !strings.Contains(err.Error(), "close failed") {
			t.Fatalf("expected close error, got %v", err)
		}
	})
}
