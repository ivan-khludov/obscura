package backup_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/backup"
)

func defaultArchiver() *backup.Archiver {
	return backup.NewArchiverForTest(backup.NewOSFileSystem())
}

type failWriter struct {
	n     int
	limit int
}

func (w *failWriter) Write(p []byte) (int, error) {
	if w.n >= w.limit {
		return 0, errors.New("write fail")
	}
	n := len(p)
	w.n += n
	return n, nil
}

func TestWriteArchive_gzipCloseError(t *testing.T) {
	a := defaultArchiver()
	err := a.WriteArchiveForTest(&failWriter{limit: 1}, nil)
	if err == nil || !strings.Contains(err.Error(), "close gzip") {
		t.Fatalf("expected close gzip error, got %v", err)
	}
}

func TestWriteArchive_tarCloseError(t *testing.T) {
	a := defaultArchiver()
	err := a.WriteArchiveForTest(&failWriter{limit: 0}, nil)
	if err == nil || !strings.Contains(err.Error(), "close tar") {
		t.Fatalf("expected close tar error, got %v", err)
	}
}

func TestReadArchive_gzipCloseError(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	data = data[:len(data)-1]
	a := defaultArchiver()
	err := a.ReadArchiveForTest(bytes.NewReader(data), t.TempDir())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestReadArchive_tarError(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write([]byte("not tar")); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	a := defaultArchiver()
	err := a.ReadArchiveForTest(bytes.NewReader(buf.Bytes()), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "tar") {
		t.Fatalf("expected tar error, got %v", err)
	}
}

func TestAddToArchive_emptyDirTree(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "empty-tree")
	if err := os.MkdirAll(filepath.Join(sub, "nested", "leaf"), 0o755); err != nil {
		t.Fatal(err)
	}
	a := defaultArchiver()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := a.AddToArchiveForTest(tw, sub); err != nil {
		t.Fatal(err)
	}
}

func TestAddToArchive_walkError(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "tree")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "missing-target"), filepath.Join(sub, "link")); err != nil {
		t.Fatal(err)
	}

	a := defaultArchiver()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err := a.AddToArchiveForTest(tw, sub)
	if err == nil {
		t.Fatal("expected walk error")
	}
}

func TestAddFile_openError(t *testing.T) {
	a := defaultArchiver()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err := a.AddFileForTest(tw, filepath.Join(t.TempDir(), "missing"), "missing")
	if err == nil || !strings.Contains(err.Error(), "open") {
		t.Fatalf("expected open error, got %v", err)
	}
}

func TestAddFile_writeHeaderError(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a.txt")
	writeFile(t, src, "x")

	a := defaultArchiver()
	tw := tar.NewWriter(&failWriter{limit: 0})
	err := a.AddFileForTest(tw, src, "a.txt")
	if err == nil {
		t.Fatal("expected write header error")
	}
}

func TestAddFile_fileInfoHeaderError(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a.txt")
	writeFile(t, src, "x")

	a := backup.NewArchiverForTestWithHeader(backup.NewOSFileSystem(), func(info os.FileInfo, name string) (*tar.Header, error) {
		return nil, errors.New("header fail")
	})
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err := a.AddFileForTest(tw, src, "a.txt")
	if err == nil || err.Error() != "header fail" {
		t.Fatalf("expected header fail, got %v", err)
	}
}

func TestAddFile_copyError(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a.txt")
	writeFile(t, src, strings.Repeat("x", 1024))

	a := defaultArchiver()
	tw := tar.NewWriter(&failWriter{limit: 200})
	err := a.AddFileForTest(tw, src, "a.txt")
	if err == nil {
		t.Fatal("expected copy error")
	}
}

func TestReadArchive_gzipCloseAfterSuccess(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a.txt")
	writeFile(t, src, "ok")
	var buf bytes.Buffer
	a := defaultArchiver()
	if err := a.WriteArchiveForTest(&buf, []string{src}); err != nil {
		t.Fatal(err)
	}
	corrupted, tryDir, err := corruptArchiveAfterExtract(t, a, buf.Bytes(), filepath.Join(dir, "try"))
	if err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(tryDir, "a.txt")); got != "ok" {
		t.Fatalf("expected extracted file, got %q", got)
	}
	err = a.ReadArchiveForTest(bytes.NewReader(corrupted), filepath.Join(dir, "out"))
	if err == nil || !strings.Contains(err.Error(), "close gzip") {
		t.Fatalf("expected close gzip error, got %v", err)
	}
}

func corruptArchiveAfterExtract(t *testing.T, a *backup.Archiver, data []byte, tryBase string) ([]byte, string, error) {
	t.Helper()
	for i := len(data) - 1; i >= 0; i-- {
		corrupted := bytes.Clone(data)
		corrupted[i] ^= 0xff
		tryDir := fmt.Sprintf("%s-%d", tryBase, i)
		_ = os.RemoveAll(tryDir)
		if err := a.ReadArchiveForTest(bytes.NewReader(corrupted), tryDir); err != nil {
			if strings.Contains(err.Error(), "close gzip") {
				if _, statErr := os.Stat(filepath.Join(tryDir, "a.txt")); statErr == nil {
					return corrupted, tryDir, nil
				}
			}
			continue
		}
	}
	return nil, "", errors.New("no gzip close corruption index found")
}
