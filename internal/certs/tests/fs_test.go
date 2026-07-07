package certs_test

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/certs"
)

type mockFS struct {
	MkdirAllFn func(path string, perm os.FileMode) error
	OpenFileFn func(path string, flag int, perm os.FileMode) (io.WriteCloser, error)
}

func (m *mockFS) MkdirAll(path string, perm os.FileMode) error {
	if m.MkdirAllFn != nil {
		return m.MkdirAllFn(path, perm)
	}
	return os.MkdirAll(path, perm)
}

func (m *mockFS) OpenFile(path string, flag int, perm os.FileMode) (io.WriteCloser, error) {
	if m.OpenFileFn != nil {
		return m.OpenFileFn(path, flag, perm)
	}
	return os.OpenFile(path, flag, perm)
}

type closeErrWriteCloser struct {
	io.WriteCloser
	closeErr error
}

func (c *closeErrWriteCloser) Close() error {
	if c.WriteCloser != nil {
		_ = c.WriteCloser.Close()
	}
	return c.closeErr
}

type failWriter struct {
	limit int
	wrote int
}

func (w *failWriter) Write(p []byte) (int, error) {
	if w.wrote >= w.limit {
		return 0, errors.New("write failed")
	}
	n := len(p)
	if w.wrote+n > w.limit {
		n = w.limit - w.wrote
	}
	w.wrote += n
	return n, nil
}

func (w *failWriter) Close() error { return nil }

func TestNewOSFileSystem(t *testing.T) {
	dir := t.TempDir()
	fs := certs.NewOSFileSystem()
	if err := fs.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "out.txt")
	f, err := fs.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateSelfSigned_certCloseError(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "test.crt")
	keyPath := filepath.Join(dir, "test.key")
	fs := &mockFS{
		OpenFileFn: func(path string, flag int, perm os.FileMode) (io.WriteCloser, error) {
			if path == certPath {
				f, err := os.OpenFile(path, flag, perm)
				if err != nil {
					return nil, err
				}
				return &closeErrWriteCloser{WriteCloser: f, closeErr: errors.New("cert close failed")}, nil
			}
			return os.OpenFile(path, flag, perm)
		},
	}
	g := certs.NewGeneratorForTest(fs)
	err := g.GenerateForTest("example.com", certPath, keyPath)
	if err == nil || !strings.Contains(err.Error(), "close cert") {
		t.Fatalf("GenerateForTest() = %v, want close cert error", err)
	}
}

func TestGenerateSelfSigned_keyCloseError(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "test.crt")
	keyPath := filepath.Join(dir, "test.key")
	fs := &mockFS{
		OpenFileFn: func(path string, flag int, perm os.FileMode) (io.WriteCloser, error) {
			if path == keyPath {
				f, err := os.OpenFile(path, flag, perm)
				if err != nil {
					return nil, err
				}
				return &closeErrWriteCloser{WriteCloser: f, closeErr: errors.New("key close failed")}, nil
			}
			return os.OpenFile(path, flag, perm)
		},
	}
	g := certs.NewGeneratorForTest(fs)
	err := g.GenerateForTest("example.com", certPath, keyPath)
	if err == nil || !strings.Contains(err.Error(), "close key") {
		t.Fatalf("GenerateForTest() = %v, want close key error", err)
	}
}

func TestGenerateSelfSigned_certEncodeError(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "test.crt")
	keyPath := filepath.Join(dir, "test.key")
	fs := &mockFS{
		OpenFileFn: func(path string, flag int, perm os.FileMode) (io.WriteCloser, error) {
			if path == certPath {
				return &failWriter{limit: 0}, nil
			}
			return os.OpenFile(path, flag, perm)
		},
	}
	g := certs.NewGeneratorForTest(fs)
	err := g.GenerateForTest("example.com", certPath, keyPath)
	if err == nil || !strings.Contains(err.Error(), "encode cert") {
		t.Fatalf("GenerateForTest() = %v, want encode cert error", err)
	}
}

func TestGenerateSelfSigned_keyEncodeError(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "test.crt")
	keyPath := filepath.Join(dir, "test.key")
	fs := &mockFS{
		OpenFileFn: func(path string, flag int, perm os.FileMode) (io.WriteCloser, error) {
			if path == keyPath {
				return &failWriter{limit: 0}, nil
			}
			return os.OpenFile(path, flag, perm)
		},
	}
	g := certs.NewGeneratorForTest(fs)
	err := g.GenerateForTest("example.com", certPath, keyPath)
	if err == nil || !strings.Contains(err.Error(), "encode key") {
		t.Fatalf("GenerateForTest() = %v, want encode key error", err)
	}
}
