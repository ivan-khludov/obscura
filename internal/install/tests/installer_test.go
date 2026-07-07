package install_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/ivan-khludov/obscura/internal/install"
)

func platformKey() string {
	return fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)
}

func buildTarGz(t *testing.T, binaryName string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	if err := tw.WriteHeader(&tar.Header{
		Name:     binaryName,
		Mode:     0o755,
		Size:     int64(len(content)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func testAssetsYAML(t *testing.T, version, sha256Hex, binaryName string) []byte {
	t.Helper()
	key := platformKey()
	return []byte(fmt.Sprintf(`version: %q
assets:
  %s:
    url: "http://example.test/sing-box.tar.gz"
    sha256: %q
    binary: %q
`, version, key, sha256Hex, binaryName))
}

func TestNewInstaller(t *testing.T) {
	inst := install.NewInstaller("/tmp/cache")
	if inst == nil || inst.HTTPClient == nil || inst.CacheDir != "/tmp/cache" {
		t.Fatalf("unexpected installer: %#v", inst)
	}
}

func TestLoadAssets(t *testing.T) {
	assets, err := install.LoadAssets()
	if err != nil {
		t.Fatal(err)
	}
	if assets.Version == "" {
		t.Fatal("expected version")
	}
	if _, ok := assets.Assets["linux-amd64"]; !ok {
		t.Fatal("expected linux-amd64 asset")
	}
}

func TestLoadAssets_readError(t *testing.T) {
	inst := &install.Installer{
		ReadEmbedded: func(string) ([]byte, error) {
			return nil, errors.New("read failed")
		},
	}
	_, err := inst.LoadAssets()
	if err == nil || !strings.Contains(err.Error(), "read assets") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadAssets_parseError(t *testing.T) {
	inst := &install.Installer{
		ReadEmbedded: func(string) ([]byte, error) {
			return []byte(":\tbad"), nil
		},
	}
	_, err := inst.LoadAssets()
	if err == nil || !strings.Contains(err.Error(), "parse assets") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVersion(t *testing.T) {
	version, err := install.Version()
	if err != nil || version == "" {
		t.Fatalf("version=%q err=%v", version, err)
	}
}

func TestInstalledVersion_missing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	_, err := install.InstalledVersion(path)
	if err == nil || !os.IsNotExist(err) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstalledVersion_defaultPath(t *testing.T) {
	inst := &install.Installer{
		Stat: func(name string) (os.FileInfo, error) {
			if name == install.DefaultInstallPath {
				return nil, os.ErrNotExist
			}
			return nil, errors.New("unexpected path")
		},
	}
	_, err := inst.InstalledVersion("")
	if !os.IsNotExist(err) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstalledVersion_withPrefix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sing-box")
	inst := &install.Installer{
		Stat: func(name string) (os.FileInfo, error) {
			if name == path {
				return nil, nil
			}
			return nil, os.ErrNotExist
		},
		RunCommand: func(name string, args ...string) ([]byte, error) {
			if name == path {
				return []byte("sing-box version 1.2.3\n"), nil
			}
			return nil, errors.New("unexpected command")
		},
	}
	got, err := inst.InstalledVersion(path)
	if err != nil || got != "1.2.3" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestInstalledVersion_plainOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sing-box")
	inst := &install.Installer{
		Stat: func(string) (os.FileInfo, error) { return nil, nil },
		RunCommand: func(string, ...string) ([]byte, error) {
			return []byte("1.2.3"), nil
		},
	}
	got, err := inst.InstalledVersion(path)
	if err != nil || got != "1.2.3" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestInstalledVersion_commandError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sing-box")
	inst := &install.Installer{
		Stat: func(string) (os.FileInfo, error) { return nil, nil },
		RunCommand: func(string, ...string) ([]byte, error) {
			return []byte("fail"), errors.New("version failed")
		},
	}
	_, err := inst.InstalledVersion(path)
	if err == nil || !strings.Contains(err.Error(), "sing-box version") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdateAvailable_missingBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-sing-box")
	available, pinned, installed, err := install.UpdateAvailable(path)
	if err != nil {
		t.Fatal(err)
	}
	if !available || pinned == "" || installed != "" {
		t.Fatalf("available=%v pinned=%q installed=%q", available, pinned, installed)
	}
}

func TestUpdateAvailable_versionCommandErrorThenMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sing-box")
	if err := os.WriteFile(path, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	statCalls := 0
	inst := &install.Installer{
		Stat: func(name string) (os.FileInfo, error) {
			statCalls++
			if statCalls == 1 {
				return nil, nil
			}
			return nil, os.ErrNotExist
		},
		RunCommand: func(string, ...string) ([]byte, error) {
			return nil, errors.New("version failed")
		},
	}
	available, pinned, installed, err := inst.UpdateAvailable(path)
	if err != nil {
		t.Fatal(err)
	}
	if !available || pinned == "" || installed != "" {
		t.Fatalf("available=%v pinned=%q installed=%q", available, pinned, installed)
	}
}

func TestUpdateAvailable_versionCommandError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sing-box")
	if err := os.WriteFile(path, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	inst := &install.Installer{
		Stat: func(string) (os.FileInfo, error) { return nil, nil },
		RunCommand: func(string, ...string) ([]byte, error) {
			return nil, errors.New("version failed")
		},
	}
	_, _, _, err := inst.UpdateAvailable(path)
	if err == nil || !strings.Contains(err.Error(), "sing-box version") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdateAvailable_upToDate(t *testing.T) {
	pinned, err := install.Version()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sing-box")
	inst := &install.Installer{
		Stat: func(string) (os.FileInfo, error) { return nil, nil },
		RunCommand: func(string, ...string) ([]byte, error) {
			return []byte("sing-box version " + pinned + "\n"), nil
		},
	}
	available, gotPinned, installed, err := inst.UpdateAvailable(path)
	if err != nil {
		t.Fatal(err)
	}
	if available || gotPinned != pinned || installed != pinned {
		t.Fatalf("available=%v pinned=%q installed=%q", available, gotPinned, installed)
	}
}

func TestUpdateAvailable_upgradeNeeded(t *testing.T) {
	pinned, err := install.Version()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sing-box")
	inst := &install.Installer{
		Stat: func(string) (os.FileInfo, error) { return nil, nil },
		RunCommand: func(string, ...string) ([]byte, error) {
			return []byte("sing-box version 0.0.1\n"), nil
		},
	}
	available, gotPinned, installed, err := inst.UpdateAvailable(path)
	if err != nil {
		t.Fatal(err)
	}
	if !available || gotPinned != pinned || installed == pinned {
		t.Fatalf("available=%v pinned=%q installed=%q", available, gotPinned, installed)
	}
}

func TestFromBytes_ok(t *testing.T) {
	data := []byte("fake-binary")
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	dest := filepath.Join(t.TempDir(), "sing-box")
	if err := install.FromBytes(data, dest, hash); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != string(data) {
		t.Fatalf("file = %q err=%v", got, err)
	}
}

func TestFromBytes_checksumMismatch(t *testing.T) {
	data := []byte("fake-binary")
	dest := filepath.Join(t.TempDir(), "sing-box")
	if err := install.FromBytes(data, dest, "deadbeef"); err == nil {
		t.Fatal("expected checksum mismatch")
	}
}

func TestFromBytes_mkdirError(t *testing.T) {
	data := []byte("fake-binary")
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	inst := &install.Installer{
		MkdirAll: func(string, os.FileMode) error {
			return errors.New("mkdir failed")
		},
	}
	err := inst.FromBytes(data, "/no/write/sing-box", hash)
	if err == nil || !strings.Contains(err.Error(), "mkdir install dir") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstaller_Install_alreadyInstalled(t *testing.T) {
	version := "9.9.9-test"
	dest := filepath.Join(t.TempDir(), "sing-box")
	progressCalled := false
	inst := &install.Installer{
		ReadEmbedded: func(string) ([]byte, error) {
			return testAssetsYAML(t, version, strings.Repeat("a", 64), "pkg/sing-box"), nil
		},
		Platform: platformKey(),
		Stat:     func(string) (os.FileInfo, error) { return nil, nil },
		RunCommand: func(string, ...string) ([]byte, error) {
			return []byte("sing-box version " + version + "\n"), nil
		},
	}
	got, err := inst.Install(dest, func(int64, int64) { progressCalled = true })
	if err != nil || got != version || !progressCalled {
		t.Fatalf("got=%q err=%v progress=%v", got, err, progressCalled)
	}
}

func TestInstaller_Install_reportProgress(t *testing.T) {
	version := "9.9.9-test"
	dest := filepath.Join(t.TempDir(), "sing-box")
	var reported []int64
	inst := &install.Installer{
		ReadEmbedded: func(string) ([]byte, error) {
			return testAssetsYAML(t, version, strings.Repeat("a", 64), "pkg/sing-box"), nil
		},
		Platform: platformKey(),
		Stat:     func(string) (os.FileInfo, error) { return nil, nil },
		RunCommand: func(string, ...string) ([]byte, error) {
			return []byte("sing-box version " + version + "\n"), nil
		},
		ReportProgress: func(onDownload func(int64, int64)) {
			onDownload(55, 100)
		},
	}
	got, err := inst.Install(dest, func(read, total int64) { reported = append(reported, read, total) })
	if err != nil || got != version {
		t.Fatalf("got=%q err=%v", got, err)
	}
	if len(reported) < 2 || reported[0] != 55 || reported[1] != 100 {
		t.Fatalf("reported=%v", reported)
	}
}

func TestInstaller_Install_success(t *testing.T) {
	version := "9.9.9-test"
	binaryName := "pkg/sing-box"
	payload := []byte("#!/bin/sh\n")
	archive := buildTarGz(t, binaryName, payload)
	sum := sha256.Sum256(archive)
	hash := hex.EncodeToString(sum[:])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(archive)))
		_, _ = w.Write(archive)
	}))
	t.Cleanup(server.Close)

	dest := filepath.Join(t.TempDir(), "sing-box")
	var progress []int64
	inst := install.NewInstaller(t.TempDir())
	inst.ReadEmbedded = func(string) ([]byte, error) {
		yaml := testAssetsYAML(t, version, hash, binaryName)
		return bytes.Replace(yaml, []byte("http://example.test/sing-box.tar.gz"), []byte(server.URL), 1), nil
	}
	inst.Stat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }

	got, err := inst.Install(dest, func(read, total int64) {
		progress = append(progress, read, total)
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != version {
		t.Fatalf("version = %q", got)
	}
	if len(progress) == 0 {
		t.Fatal("expected download progress callbacks")
	}
}

func TestInstaller_Install_unsupportedPlatform(t *testing.T) {
	inst := &install.Installer{
		ReadEmbedded: func(string) ([]byte, error) {
			return []byte(`version: "1.0.0"
assets:
  other-platform:
    url: "http://example.test/x.tar.gz"
    sha256: "abc"
    binary: "sing-box"
`), nil
		},
		Platform: "unsupported-platform",
	}
	_, err := inst.Install(filepath.Join(t.TempDir(), "sing-box"), nil)
	if err == nil || !strings.Contains(err.Error(), "unsupported platform") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstaller_Install_shaNotConfigured(t *testing.T) {
	inst := &install.Installer{
		ReadEmbedded: func(string) ([]byte, error) {
			return testAssetsYAML(t, "1.0.0", "0000000000000000000000000000000000000000000000000000000000000000", "pkg/sing-box"), nil
		},
		Platform: platformKey(),
		Stat:     func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
	}
	_, err := inst.Install(filepath.Join(t.TempDir(), "sing-box"), nil)
	if err == nil || !strings.Contains(err.Error(), "sha256 not configured") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstaller_Install_downloadError(t *testing.T) {
	inst := &install.Installer{
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("network down")
		})},
		ReadEmbedded: func(string) ([]byte, error) {
			return testAssetsYAML(t, "1.0.0", strings.Repeat("b", 64), "pkg/sing-box"), nil
		},
		Platform: platformKey(),
		Stat:     func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
	}
	_, err := inst.Install(filepath.Join(t.TempDir(), "sing-box"), nil)
	if err == nil || !strings.Contains(err.Error(), "download") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstaller_Install_badStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	inst := &install.Installer{
		ReadEmbedded: func(string) ([]byte, error) {
			yaml := testAssetsYAML(t, "1.0.0", strings.Repeat("c", 64), "pkg/sing-box")
			return bytes.Replace(yaml, []byte("http://example.test/sing-box.tar.gz"), []byte(server.URL), 1), nil
		},
		Platform: platformKey(),
		Stat:     func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
	}
	_, err := inst.Install(filepath.Join(t.TempDir(), "sing-box"), nil)
	if err == nil || !strings.Contains(err.Error(), "status 404") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstaller_Install_checksumMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not-a-valid-archive"))
	}))
	t.Cleanup(server.Close)

	inst := &install.Installer{
		ReadEmbedded: func(string) ([]byte, error) {
			yaml := testAssetsYAML(t, "1.0.0", strings.Repeat("d", 64), "pkg/sing-box")
			return bytes.Replace(yaml, []byte("http://example.test/sing-box.tar.gz"), []byte(server.URL), 1), nil
		},
		Platform: platformKey(),
		Stat:     func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
	}
	_, err := inst.Install(filepath.Join(t.TempDir(), "sing-box"), nil)
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstaller_Install_extractError(t *testing.T) {
	payload := []byte("raw-not-gzip")
	sum := sha256.Sum256(payload)
	hash := hex.EncodeToString(sum[:])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	}))
	t.Cleanup(server.Close)

	inst := &install.Installer{
		ReadEmbedded: func(string) ([]byte, error) {
			yaml := testAssetsYAML(t, "1.0.0", hash, "pkg/sing-box")
			return bytes.Replace(yaml, []byte("http://example.test/sing-box.tar.gz"), []byte(server.URL), 1), nil
		},
		Platform: platformKey(),
		Stat:     func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
	}
	_, err := inst.Install(filepath.Join(t.TempDir(), "sing-box"), nil)
	if err == nil || !strings.Contains(err.Error(), "gzip open") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstaller_Install_binaryNotFound(t *testing.T) {
	archive := buildTarGz(t, "other/file", []byte("x"))
	sum := sha256.Sum256(archive)
	hash := hex.EncodeToString(sum[:])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	}))
	t.Cleanup(server.Close)

	inst := &install.Installer{
		ReadEmbedded: func(string) ([]byte, error) {
			yaml := testAssetsYAML(t, "1.0.0", hash, "missing/sing-box")
			return bytes.Replace(yaml, []byte("http://example.test/sing-box.tar.gz"), []byte(server.URL), 1), nil
		},
		Platform: platformKey(),
		Stat:     func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
	}
	_, err := inst.Install(filepath.Join(t.TempDir(), "sing-box"), nil)
	if err == nil || !strings.Contains(err.Error(), "not found in archive") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstaller_Install_writeBusy(t *testing.T) {
	version := "9.9.9-test"
	binaryName := "pkg/sing-box"
	payload := []byte("bin")
	archive := buildTarGz(t, binaryName, payload)
	sum := sha256.Sum256(archive)
	hash := hex.EncodeToString(sum[:])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	}))
	t.Cleanup(server.Close)

	dest := filepath.Join(t.TempDir(), "sing-box")
	inst := &install.Installer{
		ReadEmbedded: func(string) ([]byte, error) {
			yaml := testAssetsYAML(t, version, hash, binaryName)
			return bytes.Replace(yaml, []byte("http://example.test/sing-box.tar.gz"), []byte(server.URL), 1), nil
		},
		Platform: platformKey(),
		Stat:     func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		MkdirAll: func(string, os.FileMode) error { return nil },
		WriteFile: func(string, []byte, os.FileMode) error {
			return fmt.Errorf("write failed: %w", syscall.ETXTBSY)
		},
	}
	_, err := inst.Install(dest, nil)
	if err == nil || !strings.Contains(err.Error(), "stop sing-box before updating") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstaller_Install_renameBusy(t *testing.T) {
	version := "9.9.9-test"
	binaryName := "pkg/sing-box"
	payload := []byte("bin")
	archive := buildTarGz(t, binaryName, payload)
	sum := sha256.Sum256(archive)
	hash := hex.EncodeToString(sum[:])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	}))
	t.Cleanup(server.Close)

	dest := filepath.Join(t.TempDir(), "sing-box")
	removed := false
	inst := &install.Installer{
		ReadEmbedded: func(string) ([]byte, error) {
			yaml := testAssetsYAML(t, version, hash, binaryName)
			return bytes.Replace(yaml, []byte("http://example.test/sing-box.tar.gz"), []byte(server.URL), 1), nil
		},
		Platform:  platformKey(),
		Stat:      func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		MkdirAll:  func(string, os.FileMode) error { return nil },
		WriteFile: func(string, []byte, os.FileMode) error { return nil },
		Rename: func(string, string) error {
			return errors.New("text file busy")
		},
		Remove: func(string) error {
			removed = true
			return nil
		},
	}
	_, err := inst.Install(dest, nil)
	if err == nil || !strings.Contains(err.Error(), "stop sing-box before updating") || !removed {
		t.Fatalf("err=%v removed=%v", err, removed)
	}
}

func TestInstaller_Install_readError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "1")
		_, _ = w.Write([]byte("x"))
	}))
	t.Cleanup(server.Close)

	inst := &install.Installer{
		ReadEmbedded: func(string) ([]byte, error) {
			yaml := testAssetsYAML(t, "1.0.0", strings.Repeat("e", 64), "pkg/sing-box")
			return bytes.Replace(yaml, []byte("http://example.test/sing-box.tar.gz"), []byte(server.URL), 1), nil
		},
		Platform: platformKey(),
		Stat:     func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(errReader{}),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		})},
	}
	_, err := inst.Install(filepath.Join(t.TempDir(), "sing-box"), func(int64, int64) {})
	if err == nil || !strings.Contains(err.Error(), "read ") {
		t.Fatalf("unexpected error: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func TestInstaller_Install_closeBodyError(t *testing.T) {
	binaryName := "pkg/sing-box"
	payload := []byte("bin")
	archive := buildTarGz(t, binaryName, payload)
	sum := sha256.Sum256(archive)
	hash := hex.EncodeToString(sum[:])
	inst := &install.Installer{
		ReadEmbedded: func(string) ([]byte, error) {
			return testAssetsYAML(t, "1.0.0", hash, binaryName), nil
		},
		Platform:  platformKey(),
		Stat:      func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		MkdirAll:  func(string, os.FileMode) error { return nil },
		WriteFile: func(string, []byte, os.FileMode) error { return nil },
		Rename:    func(string, string) error { return nil },
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       &closeErrReader{data: archive},
				Header:     make(http.Header),
				Request:    req,
			}, nil
		})},
	}
	_, err := inst.Install(filepath.Join(t.TempDir(), "sing-box"), nil)
	if err == nil || !strings.Contains(err.Error(), "close response body") {
		t.Fatalf("unexpected error: %v", err)
	}
}

type closeErrReader struct {
	data []byte
	read bool
}

func (c *closeErrReader) Read(p []byte) (int, error) {
	if c.read {
		return 0, io.EOF
	}
	c.read = true
	n := copy(p, c.data)
	return n, nil
}

func (c *closeErrReader) Close() error { return errors.New("close failed") }

func TestExtractBinary_matchesBaseName(t *testing.T) {
	version := "1.0.0"
	binaryName := "deep/path/sing-box"
	payload := []byte("bin")
	archive := buildTarGz(t, "sing-box", payload)
	sum := sha256.Sum256(archive)
	hash := hex.EncodeToString(sum[:])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	}))
	t.Cleanup(server.Close)

	dest := filepath.Join(t.TempDir(), "sing-box")
	inst := &install.Installer{
		ReadEmbedded: func(string) ([]byte, error) {
			yaml := testAssetsYAML(t, version, hash, binaryName)
			return bytes.Replace(yaml, []byte("http://example.test/sing-box.tar.gz"), []byte(server.URL), 1), nil
		},
		Platform:  platformKey(),
		Stat:      func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		MkdirAll:  func(string, os.FileMode) error { return nil },
		WriteFile: func(string, []byte, os.FileMode) error { return nil },
		Rename:    func(string, string) error { return nil },
	}
	if _, err := inst.Install(dest, nil); err != nil {
		t.Fatal(err)
	}
}

func TestInstalledVersion_defaultRunCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sing-box")
	if err := os.WriteFile(path, []byte("not executable"), 0o644); err != nil {
		t.Fatal(err)
	}
	inst := &install.Installer{}
	_, err := inst.InstalledVersion(path)
	if err == nil || !strings.Contains(err.Error(), "sing-box version") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstaller_Install_writePlainError(t *testing.T) {
	version := "9.9.9-test"
	binaryName := "pkg/sing-box"
	payload := []byte("bin")
	archive := buildTarGz(t, binaryName, payload)
	sum := sha256.Sum256(archive)
	hash := hex.EncodeToString(sum[:])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	}))
	t.Cleanup(server.Close)

	dest := filepath.Join(t.TempDir(), "sing-box")
	inst := &install.Installer{
		ReadEmbedded: func(string) ([]byte, error) {
			yaml := testAssetsYAML(t, version, hash, binaryName)
			return bytes.Replace(yaml, []byte("http://example.test/sing-box.tar.gz"), []byte(server.URL), 1), nil
		},
		Platform: platformKey(),
		Stat:     func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		MkdirAll: func(string, os.FileMode) error { return nil },
		WriteFile: func(string, []byte, os.FileMode) error {
			return errors.New("plain write failed")
		},
	}
	_, err := inst.Install(dest, nil)
	if err == nil || !strings.Contains(err.Error(), "plain write failed") || strings.Contains(err.Error(), "stop sing-box") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstaller_Install_renameUsesDefaultRemove(t *testing.T) {
	version := "9.9.9-test"
	binaryName := "pkg/sing-box"
	payload := []byte("bin")
	archive := buildTarGz(t, binaryName, payload)
	sum := sha256.Sum256(archive)
	hash := hex.EncodeToString(sum[:])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	}))
	t.Cleanup(server.Close)

	dest := filepath.Join(t.TempDir(), "sing-box")
	tmpPath := dest + ".new"
	inst := &install.Installer{
		ReadEmbedded: func(string) ([]byte, error) {
			yaml := testAssetsYAML(t, version, hash, binaryName)
			return bytes.Replace(yaml, []byte("http://example.test/sing-box.tar.gz"), []byte(server.URL), 1), nil
		},
		Platform: platformKey(),
		Stat:     func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		Rename: func(string, string) error {
			return errors.New("rename failed")
		},
	}
	_, err := inst.Install(dest, nil)
	if err == nil || !strings.Contains(err.Error(), "rename failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(tmpPath); !os.IsNotExist(statErr) {
		t.Fatalf("expected temp file removed, stat err=%v", statErr)
	}
}

func TestUpdateAvailable_defaultPath(t *testing.T) {
	available, _, _, err := install.UpdateAvailable("")
	if err != nil {
		t.Fatal(err)
	}
	if !available {
		t.Fatal("expected update available for missing default binary")
	}
}

func TestExtractBinary_exactPath(t *testing.T) {
	binaryName := "exact/path/sing-box"
	payload := []byte("bin")
	archive := buildTarGz(t, binaryName, payload)
	sum := sha256.Sum256(archive)
	hash := hex.EncodeToString(sum[:])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	}))
	t.Cleanup(server.Close)

	dest := filepath.Join(t.TempDir(), "sing-box")
	inst := &install.Installer{
		ReadEmbedded: func(string) ([]byte, error) {
			yaml := testAssetsYAML(t, "1.0.0", hash, binaryName)
			return bytes.Replace(yaml, []byte("http://example.test/sing-box.tar.gz"), []byte(server.URL), 1), nil
		},
		Platform:  platformKey(),
		Stat:      func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		MkdirAll:  func(string, os.FileMode) error { return nil },
		WriteFile: func(string, []byte, os.FileMode) error { return nil },
		Rename:    func(string, string) error { return nil },
	}
	if _, err := inst.Install(dest, nil); err != nil {
		t.Fatal(err)
	}
}

func TestExtractBinary_skipsNonRegular(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	if err := tw.WriteHeader(&tar.Header{
		Name:     "pkg/sing-box",
		Typeflag: tar.TypeSymlink,
		Linkname: "elsewhere",
	}); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{
		Name:     "other/sing-box",
		Mode:     0o755,
		Size:     3,
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("bin")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	archive := buf.Bytes()
	sum := sha256.Sum256(archive)
	hash := hex.EncodeToString(sum[:])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	}))
	t.Cleanup(server.Close)

	dest := filepath.Join(t.TempDir(), "sing-box")
	inst := &install.Installer{
		ReadEmbedded: func(string) ([]byte, error) {
			yaml := testAssetsYAML(t, "1.0.0", hash, "missing/sing-box")
			return bytes.Replace(yaml, []byte("http://example.test/sing-box.tar.gz"), []byte(server.URL), 1), nil
		},
		Platform:  platformKey(),
		Stat:      func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		MkdirAll:  func(string, os.FileMode) error { return nil },
		WriteFile: func(string, []byte, os.FileMode) error { return nil },
		Rename:    func(string, string) error { return nil },
	}
	if _, err := inst.Install(dest, nil); err != nil {
		t.Fatal(err)
	}
}

func TestExtractBinary_tarReadError(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write([]byte("partial")); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	archive := buf.Bytes()
	sum := sha256.Sum256(archive)
	hash := hex.EncodeToString(sum[:])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	}))
	t.Cleanup(server.Close)

	inst := &install.Installer{
		ReadEmbedded: func(string) ([]byte, error) {
			yaml := testAssetsYAML(t, "1.0.0", hash, "pkg/sing-box")
			return bytes.Replace(yaml, []byte("http://example.test/sing-box.tar.gz"), []byte(server.URL), 1), nil
		},
		Platform: platformKey(),
		Stat:     func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
	}
	_, err := inst.Install(filepath.Join(t.TempDir(), "sing-box"), nil)
	if err == nil || !strings.Contains(err.Error(), "tar read") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtractBinary_skipsUnrelatedEntries(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	if err := tw.WriteHeader(&tar.Header{
		Name:     "README.txt",
		Mode:     0o644,
		Size:     5,
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	binaryName := "pkg/sing-box"
	payload := []byte("bin")
	if err := tw.WriteHeader(&tar.Header{
		Name:     binaryName,
		Mode:     0o755,
		Size:     int64(len(payload)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	archive := buf.Bytes()
	sum := sha256.Sum256(archive)
	hash := hex.EncodeToString(sum[:])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	}))
	t.Cleanup(server.Close)

	dest := filepath.Join(t.TempDir(), "sing-box")
	inst := &install.Installer{
		ReadEmbedded: func(string) ([]byte, error) {
			yaml := testAssetsYAML(t, "1.0.0", hash, binaryName)
			return bytes.Replace(yaml, []byte("http://example.test/sing-box.tar.gz"), []byte(server.URL), 1), nil
		},
		Platform:  platformKey(),
		Stat:      func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		MkdirAll:  func(string, os.FileMode) error { return nil },
		WriteFile: func(string, []byte, os.FileMode) error { return nil },
		Rename:    func(string, string) error { return nil },
	}
	if _, err := inst.Install(dest, nil); err != nil {
		t.Fatal(err)
	}
}

func TestInstaller_Install_mkdirError(t *testing.T) {
	version := "1.0.0"
	binaryName := "pkg/sing-box"
	payload := []byte("bin")
	archive := buildTarGz(t, binaryName, payload)
	sum := sha256.Sum256(archive)
	hash := hex.EncodeToString(sum[:])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	}))
	t.Cleanup(server.Close)

	inst := &install.Installer{
		ReadEmbedded: func(string) ([]byte, error) {
			yaml := testAssetsYAML(t, version, hash, binaryName)
			return bytes.Replace(yaml, []byte("http://example.test/sing-box.tar.gz"), []byte(server.URL), 1), nil
		},
		Platform: platformKey(),
		Stat:     func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		MkdirAll: func(string, os.FileMode) error { return errors.New("mkdir failed") },
	}
	_, err := inst.Install(filepath.Join(t.TempDir(), "sing-box"), nil)
	if err == nil || !strings.Contains(err.Error(), "mkdir install dir") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstaller_Install_loadAssetsError(t *testing.T) {
	inst := &install.Installer{
		ReadEmbedded: func(string) ([]byte, error) { return nil, errors.New("missing assets") },
	}
	_, err := inst.Install(filepath.Join(t.TempDir(), "sing-box"), nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestUpdateAvailable_loadAssetsError(t *testing.T) {
	inst := &install.Installer{
		ReadEmbedded: func(string) ([]byte, error) { return nil, errors.New("missing assets") },
	}
	_, _, _, err := inst.UpdateAvailable(filepath.Join(t.TempDir(), "sing-box"))
	if err == nil {
		t.Fatal("expected error")
	}
}
