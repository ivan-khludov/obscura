package backup_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/backup"
)

func TestDefaultBackupName(t *testing.T) {
	name := backup.DefaultBackupName()
	re := regexp.MustCompile(`^obscura-backup-\d{8}-\d{6}\.tar\.gz$`)
	if !re.MatchString(name) {
		t.Fatalf("unexpected name format: %q", name)
	}
}

func TestCreateRestore_roundtrip(t *testing.T) {
	dir := t.TempDir()
	srcFile := filepath.Join(dir, "state.db")
	writeFile(t, srcFile, "db-content")
	srcDir := filepath.Join(dir, "configs")
	writeFile(t, filepath.Join(srcDir, "nested", "a.json"), `{"a":1}`)
	writeFile(t, filepath.Join(srcDir, "b.json"), `{"b":2}`)

	archive := filepath.Join(dir, "backup.tar.gz")
	if err := backup.Create(archive, []string{srcFile, srcDir}); err != nil {
		t.Fatal(err)
	}

	restoreDir := filepath.Join(dir, "restored")
	if err := backup.Restore(archive, restoreDir); err != nil {
		t.Fatal(err)
	}

	if got := readFile(t, filepath.Join(restoreDir, "state.db")); got != "db-content" {
		t.Fatalf("state.db: got %q", got)
	}
	if got := readFile(t, filepath.Join(restoreDir, "configs", "nested", "a.json")); got != `{"a":1}` {
		t.Fatalf("a.json: got %q", got)
	}
	if got := readFile(t, filepath.Join(restoreDir, "configs", "b.json")); got != `{"b":2}` {
		t.Fatalf("b.json: got %q", got)
	}
}

func TestCreate_skipsMissingSource(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "exists.txt")
	writeFile(t, src, "ok")
	archive := filepath.Join(dir, "backup.tar.gz")
	if err := backup.Create(archive, []string{src, filepath.Join(dir, "missing")}); err != nil {
		t.Fatal(err)
	}
	restoreDir := filepath.Join(dir, "restored")
	if err := backup.Restore(archive, restoreDir); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(restoreDir, "exists.txt")); got != "ok" {
		t.Fatalf("got %q", got)
	}
}

func TestCreate_destCreateError(t *testing.T) {
	dir := t.TempDir()
	err := backup.Create(dir, []string{filepath.Join(dir, "x")})
	if err == nil || !strings.Contains(err.Error(), "create backup") {
		t.Fatalf("expected create backup error, got %v", err)
	}
}

func TestCreate_unreadableSource(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "secret")
	writeFile(t, src, "hidden")
	if err := os.Chmod(src, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(src, 0o600) })

	archive := filepath.Join(dir, "backup.tar.gz")
	err := backup.Create(archive, []string{src})
	if err == nil || !strings.Contains(err.Error(), "open") {
		t.Fatalf("expected open error, got %v", err)
	}
}

func TestCreate_walkOpenError(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "tree")
	writeFile(t, filepath.Join(sub, "ok.txt"), "ok")
	secret := filepath.Join(sub, "secret.txt")
	writeFile(t, secret, "hidden")
	if err := os.Chmod(secret, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(secret, 0o600) })

	archive := filepath.Join(dir, "backup.tar.gz")
	err := backup.Create(archive, []string{sub})
	if err == nil || !strings.Contains(err.Error(), "open") {
		t.Fatalf("expected open error, got %v", err)
	}
}

func TestRestore_openError(t *testing.T) {
	err := backup.Restore(filepath.Join(t.TempDir(), "missing.tar.gz"), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "open backup") {
		t.Fatalf("expected open backup error, got %v", err)
	}
}

func TestRestore_invalidGzip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.gz")
	writeFile(t, path, "not gzip")
	err := backup.Restore(path, filepath.Join(dir, "out"))
	if err == nil || !strings.Contains(err.Error(), "gzip") {
		t.Fatalf("expected gzip error, got %v", err)
	}
}

func TestRestore_corruptTar(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.tar.gz")
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write([]byte("not a tar")); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, buf.String())
	err := backup.Restore(path, filepath.Join(dir, "out"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRestore_mkdirError(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "f.txt")
	writeFile(t, src, "x")
	archive := filepath.Join(dir, "backup.tar.gz")
	if err := backup.Create(archive, []string{src}); err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(dir, "blocker")
	writeFile(t, blocker, "file")
	err := backup.Restore(archive, blocker)
	if err == nil {
		t.Fatal("expected mkdir error")
	}
}

func TestRestore_openFileError(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "f.txt")
	writeFile(t, src, "x")
	archive := filepath.Join(dir, "backup.tar.gz")
	if err := backup.Create(archive, []string{src}); err != nil {
		t.Fatal(err)
	}
	restoreDir := filepath.Join(dir, "ro")
	if err := os.Mkdir(restoreDir, 0o555); err != nil {
		t.Fatal(err)
	}
	err := backup.Restore(archive, restoreDir)
	if err == nil {
		t.Fatal("expected open file error")
	}
}

func TestRestore_copyError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad-size.tar.gz")
	writeTruncatedTarGz(t, path, "big.bin", 1024, []byte("short"))
	err := backup.Restore(path, filepath.Join(dir, "out"))
	if err == nil {
		t.Fatal("expected copy error")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func writeTruncatedTarGz(t *testing.T, path, name string, size int64, data []byte) {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	hdr := &tar.Header{Name: name, Mode: 0o644, Size: size}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}
