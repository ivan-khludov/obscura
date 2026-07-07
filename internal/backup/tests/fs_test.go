package backup_test

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/backup"
)

type mockFS struct {
	CreateFn   func(name string) (io.WriteCloser, error)
	OpenFn     func(name string) (backup.ReadStatFile, error)
	OpenFileFn func(path string, flag int, perm os.FileMode) (io.WriteCloser, error)
	StatFn     func(name string) (os.FileInfo, error)
	MkdirAllFn func(path string, perm os.FileMode) error
	WalkFn     func(root string, fn filepath.WalkFunc) error
	RelFn      func(basepath, targpath string) (string, error)
}

func (m *mockFS) Create(name string) (io.WriteCloser, error) {
	if m.CreateFn != nil {
		return m.CreateFn(name)
	}
	return os.Create(name)
}

func (m *mockFS) Open(name string) (backup.ReadStatFile, error) {
	if m.OpenFn != nil {
		return m.OpenFn(name)
	}
	return os.Open(name)
}

func (m *mockFS) OpenFile(path string, flag int, perm os.FileMode) (io.WriteCloser, error) {
	if m.OpenFileFn != nil {
		return m.OpenFileFn(path, flag, perm)
	}
	return os.OpenFile(path, flag, perm)
}

func (m *mockFS) Stat(name string) (os.FileInfo, error) {
	if m.StatFn != nil {
		return m.StatFn(name)
	}
	return os.Stat(name)
}

func (m *mockFS) MkdirAll(path string, perm os.FileMode) error {
	if m.MkdirAllFn != nil {
		return m.MkdirAllFn(path, perm)
	}
	return os.MkdirAll(path, perm)
}

func (m *mockFS) Walk(root string, fn filepath.WalkFunc) error {
	if m.WalkFn != nil {
		return m.WalkFn(root, fn)
	}
	return filepath.Walk(root, fn)
}

func (m *mockFS) Rel(basepath, targpath string) (string, error) {
	if m.RelFn != nil {
		return m.RelFn(basepath, targpath)
	}
	return filepath.Rel(basepath, targpath)
}

type closeErrWriteCloser struct {
	io.WriteCloser
	closeErr error
}

func (c *closeErrWriteCloser) Close() error {
	if c.WriteCloser != nil {
		_ = c.WriteCloser.Close()
	}
	if c.closeErr != nil {
		return c.closeErr
	}
	return errCloseFail
}

type closeErrReadStatFile struct {
	backup.ReadStatFile
	closeErr error
}

func (c *closeErrReadStatFile) Close() error {
	if c.ReadStatFile != nil {
		_ = c.ReadStatFile.Close()
	}
	if c.closeErr != nil {
		return c.closeErr
	}
	return errCloseFail
}

type statErrReadStatFile struct {
	backup.ReadStatFile
	statErr error
}

func (s *statErrReadStatFile) Stat() (os.FileInfo, error) {
	if s.statErr != nil {
		return nil, s.statErr
	}
	return s.ReadStatFile.Stat()
}

var errCloseFail = errors.New("close fail")

func TestCreate_closeBackupError(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a.txt")
	writeFile(t, src, "x")
	archive := filepath.Join(dir, "backup.tar.gz")

	fs := &mockFS{
		CreateFn: func(name string) (io.WriteCloser, error) {
			f, err := os.Create(name)
			if err != nil {
				return nil, err
			}
			return &closeErrWriteCloser{WriteCloser: f}, nil
		},
	}
	a := backup.NewArchiverForTest(fs)
	err := a.Create(archive, []string{src})
	if err == nil || !strings.Contains(err.Error(), "close backup") {
		t.Fatalf("expected close backup error, got %v", err)
	}
}

func TestRestore_closeBackupError(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a.txt")
	writeFile(t, src, "x")
	archive := filepath.Join(dir, "backup.tar.gz")
	if err := backup.Create(archive, []string{src}); err != nil {
		t.Fatal(err)
	}

	fs := &mockFS{
		OpenFn: func(name string) (backup.ReadStatFile, error) {
			f, err := os.Open(name)
			if err != nil {
				return nil, err
			}
			return &closeErrReadStatFile{ReadStatFile: f}, nil
		},
	}
	a := backup.NewArchiverForTest(fs)
	err := a.Restore(archive, filepath.Join(dir, "out"))
	if err == nil || !strings.Contains(err.Error(), "close backup") {
		t.Fatalf("expected close backup error, got %v", err)
	}
}

func TestAddFile_closeError(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a.txt")
	writeFile(t, src, "x")

	fs := &mockFS{
		OpenFn: func(name string) (backup.ReadStatFile, error) {
			f, err := os.Open(name)
			if err != nil {
				return nil, err
			}
			return &closeErrReadStatFile{ReadStatFile: f}, nil
		},
	}
	a := backup.NewArchiverForTest(fs)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := a.AddFileForTest(tw, src, "a.txt"); err == nil {
		t.Fatal("expected close error")
	}
}

func TestAddToArchive_statError(t *testing.T) {
	fs := &mockFS{
		StatFn: func(name string) (os.FileInfo, error) {
			return nil, errors.New("stat fail")
		},
	}
	a := backup.NewArchiverForTest(fs)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err := a.AddToArchiveForTest(tw, "/any")
	if err == nil || !strings.Contains(err.Error(), "stat") {
		t.Fatalf("expected stat error, got %v", err)
	}
}

func TestAddToArchive_filepathRelError(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "tree")
	writeFile(t, filepath.Join(sub, "f.txt"), "x")

	fs := &mockFS{
		RelFn: func(base, targpath string) (string, error) {
			return "", errors.New("rel fail")
		},
	}
	a := backup.NewArchiverForTest(fs)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err := a.AddToArchiveForTest(tw, sub)
	if err == nil || !strings.Contains(err.Error(), "rel fail") {
		t.Fatalf("expected rel error, got %v", err)
	}
}

func TestRestore_copyCloseError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad-size.tar.gz")
	writeTruncatedTarGz(t, path, "big.bin", 1024, []byte("short"))

	fs := &mockFS{
		OpenFileFn: func(name string, flag int, perm os.FileMode) (io.WriteCloser, error) {
			f, err := os.OpenFile(name, flag, perm)
			if err != nil {
				return nil, err
			}
			return &closeErrWriteCloser{WriteCloser: f}, nil
		},
	}
	a := backup.NewArchiverForTest(fs)
	err := a.Restore(path, filepath.Join(dir, "out"))
	if err == nil || !strings.Contains(err.Error(), "close:") {
		t.Fatalf("expected copy+close error, got %v", err)
	}
}

func TestRestore_outCloseError(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a.txt")
	writeFile(t, src, "ok")
	archive := filepath.Join(dir, "backup.tar.gz")
	if err := backup.Create(archive, []string{src}); err != nil {
		t.Fatal(err)
	}

	fs := &mockFS{
		OpenFileFn: func(name string, flag int, perm os.FileMode) (io.WriteCloser, error) {
			f, err := os.OpenFile(name, flag, perm)
			if err != nil {
				return nil, err
			}
			return &closeErrWriteCloser{WriteCloser: f}, nil
		},
	}
	a := backup.NewArchiverForTest(fs)
	err := a.Restore(archive, filepath.Join(dir, "out"))
	if err == nil || err.Error() != "close fail" {
		t.Fatalf("expected close fail, got %v", err)
	}
}

func TestAddToArchive_walkCallbackError(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "tree")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	fs := &mockFS{
		WalkFn: func(path string, fn filepath.WalkFunc) error {
			return fn(path, nil, errors.New("walk fail"))
		},
	}
	a := backup.NewArchiverForTest(fs)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err := a.AddToArchiveForTest(tw, sub)
	if err == nil || err.Error() != "walk fail" {
		t.Fatalf("expected walk fail, got %v", err)
	}
}

func TestAddFile_statError(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a.txt")
	writeFile(t, src, "x")

	fs := &mockFS{
		OpenFn: func(name string) (backup.ReadStatFile, error) {
			f, err := os.Open(name)
			if err != nil {
				return nil, err
			}
			return &statErrReadStatFile{ReadStatFile: f, statErr: errors.New("stat fail")}, nil
		},
	}
	a := backup.NewArchiverForTest(fs)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err := a.AddFileForTest(tw, src, "a.txt")
	if err == nil || err.Error() != "stat fail" {
		t.Fatalf("expected stat fail, got %v", err)
	}
}
