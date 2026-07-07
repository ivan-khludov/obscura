// Package install downloads and verifies sing-box release artifacts.
package install

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed assets.yaml
var assetsFS embed.FS

// DefaultInstallPath is the default sing-box binary install location.
const DefaultInstallPath = "/usr/local/bin/sing-box"

type assetsFile struct {
	Version string                `yaml:"version"`
	Assets  map[string]assetEntry `yaml:"assets"`
}

type assetEntry struct {
	URL    string `yaml:"url"`
	SHA256 string `yaml:"sha256"`
	Binary string `yaml:"binary"`
}

// Installer downloads and installs sing-box with checksum verification.
type Installer struct {
	HTTPClient   *http.Client
	CacheDir     string
	Platform     string
	Stat         func(name string) (os.FileInfo, error)
	MkdirAll     func(path string, perm os.FileMode) error
	WriteFile    func(name string, data []byte, perm os.FileMode) error
	Rename       func(oldpath, newpath string) error
	Remove       func(name string) error
	RunCommand   func(name string, args ...string) ([]byte, error)
	ReadEmbedded func(name string) ([]byte, error)
	// ReportProgress, when set, is invoked at the start of Install (for tests).
	ReportProgress func(onDownload func(bytesRead, totalBytes int64))
}

func (i *Installer) stat(name string) (os.FileInfo, error) {
	if i != nil && i.Stat != nil {
		return i.Stat(name)
	}
	return os.Stat(name)
}

func (i *Installer) mkdirAll(path string, perm os.FileMode) error {
	if i != nil && i.MkdirAll != nil {
		return i.MkdirAll(path, perm)
	}
	return os.MkdirAll(path, perm)
}

func (i *Installer) writeFile(name string, data []byte, perm os.FileMode) error {
	if i != nil && i.WriteFile != nil {
		return i.WriteFile(name, data, perm)
	}
	return os.WriteFile(name, data, perm)
}

func (i *Installer) rename(oldpath, newpath string) error {
	if i != nil && i.Rename != nil {
		return i.Rename(oldpath, newpath)
	}
	return os.Rename(oldpath, newpath)
}

func (i *Installer) remove(name string) error {
	if i != nil && i.Remove != nil {
		return i.Remove(name)
	}
	return os.Remove(name)
}

func (i *Installer) runCommand(name string, args ...string) ([]byte, error) {
	if i != nil && i.RunCommand != nil {
		return i.RunCommand(name, args...)
	}
	return exec.Command(name, args...).CombinedOutput()
}

func (i *Installer) readEmbedded(name string) ([]byte, error) {
	if i != nil && i.ReadEmbedded != nil {
		return i.ReadEmbedded(name)
	}
	return assetsFS.ReadFile(name)
}

func (i *Installer) platformKey() string {
	if i != nil && i.Platform != "" {
		return i.Platform
	}
	return fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)
}

// NewInstaller returns an Installer with default HTTP client.
func NewInstaller(cacheDir string) *Installer {
	return &Installer{
		HTTPClient: &http.Client{Timeout: 15 * time.Minute},
		CacheDir:   cacheDir,
	}
}

// LoadAssets reads embedded assets.yaml release metadata.
func LoadAssets() (*assetsFile, error) {
	return (&Installer{}).LoadAssets()
}

// LoadAssets reads embedded assets.yaml release metadata.
func (i *Installer) LoadAssets() (*assetsFile, error) {
	return i.loadAssets()
}

func (i *Installer) loadAssets() (*assetsFile, error) {
	raw, err := i.readEmbedded("assets.yaml")
	if err != nil {
		return nil, fmt.Errorf("read assets: %w", err)
	}
	var file assetsFile
	if err := yaml.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("parse assets: %w", err)
	}
	return &file, nil
}

// Version returns the pinned sing-box version from assets.yaml.
func Version() (string, error) {
	return (&Installer{}).pinnedVersion()
}

// InstalledVersion returns the version string from an installed sing-box binary.
func InstalledVersion(binaryPath string) (string, error) {
	return (&Installer{}).InstalledVersion(binaryPath)
}

// InstalledVersion returns the version string from an installed sing-box binary.
func (i *Installer) InstalledVersion(binaryPath string) (string, error) {
	return i.installedVersion(binaryPath)
}

func (i *Installer) installedVersion(binaryPath string) (string, error) {
	if binaryPath == "" {
		binaryPath = DefaultInstallPath
	}
	if _, err := i.stat(binaryPath); err != nil {
		return "", err
	}
	out, err := i.runCommand(binaryPath, "version")
	if err != nil {
		return "", fmt.Errorf("sing-box version: %w", err)
	}
	return parseVersionOutput(string(out)), nil
}

// UpdateAvailable reports whether sing-box should be installed or upgraded.
func UpdateAvailable(binaryPath string) (available bool, pinned, installed string, err error) {
	return (&Installer{}).UpdateAvailable(binaryPath)
}

func (i *Installer) pinnedVersion() (string, error) {
	assets, err := i.loadAssets()
	if err != nil {
		return "", err
	}
	return assets.Version, nil
}

// UpdateAvailable reports whether sing-box should be installed or upgraded.
func (i *Installer) UpdateAvailable(binaryPath string) (available bool, pinned, installed string, err error) {
	if binaryPath == "" {
		binaryPath = DefaultInstallPath
	}
	pinned, err = i.pinnedVersion()
	if err != nil {
		return false, "", "", err
	}
	installed, err = i.installedVersion(binaryPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || os.IsNotExist(err) {
			return true, pinned, "", nil
		}
		if _, statErr := i.stat(binaryPath); statErr != nil && (os.IsNotExist(statErr) || errors.Is(statErr, os.ErrNotExist)) {
			return true, pinned, "", nil
		}
		return false, pinned, "", err
	}
	return installed != pinned, pinned, installed, nil
}

// parseVersionOutput parses protocol or configuration data.
func parseVersionOutput(s string) string {
	s = strings.TrimSpace(s)
	const prefix = "sing-box version "
	if strings.HasPrefix(s, prefix) {
		return strings.TrimSpace(s[len(prefix):])
	}
	return s
}

// Install downloads the sing-box binary for the current platform and installs it to destPath.
func (i *Installer) Install(destPath string, onDownload func(bytesRead, totalBytes int64)) (string, error) {
	if i != nil && i.ReportProgress != nil && onDownload != nil {
		i.ReportProgress(onDownload)
	}
	assets, err := i.loadAssets()
	if err != nil {
		return "", err
	}
	key := i.platformKey()
	entry, ok := assets.Assets[key]
	if !ok {
		return "", fmt.Errorf("unsupported platform %s", key)
	}
	if strings.HasPrefix(entry.SHA256, "000000000000") {
		return "", fmt.Errorf("sha256 not configured for %s in assets.yaml", key)
	}
	if installed, err := i.installedVersion(destPath); err == nil && installed == assets.Version {
		if onDownload != nil {
			onDownload(1, 1)
		}
		return assets.Version, nil
	}
	data, err := i.download(entry.URL, onDownload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != strings.ToLower(entry.SHA256) {
		return "", fmt.Errorf("checksum mismatch for %s", entry.URL)
	}
	binaryData, err := extractBinary(data, entry.Binary)
	if err != nil {
		return "", err
	}
	if err := i.mkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return "", fmt.Errorf("mkdir install dir: %w", err)
	}
	tmpPath := destPath + ".new"
	if err := i.writeFile(tmpPath, binaryData, 0o755); err != nil {
		return "", fmt.Errorf("write binary: %w", wrapBusyBinaryErr(err))
	}
	if err := i.rename(tmpPath, destPath); err != nil {
		_ = i.remove(tmpPath)
		return "", fmt.Errorf("install binary: %w", wrapBusyBinaryErr(err))
	}
	return assets.Version, nil
}

// wrapBusyBinaryErr performs an internal helper operation.
func wrapBusyBinaryErr(err error) error {
	if errors.Is(err, syscall.ETXTBSY) || strings.Contains(err.Error(), "text file busy") {
		return fmt.Errorf("%w (stop sing-box before updating)", err)
	}
	return err
}

// download fetches raw bytes from url.
func (i *Installer) download(url string, onDownload func(bytesRead, totalBytes int64)) (data []byte, err error) {
	client := i.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close response body: %w", cerr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: status %d", url, resp.StatusCode)
	}
	total := resp.ContentLength
	if onDownload != nil {
		onDownload(0, total)
	}
	reader := io.Reader(resp.Body)
	if onDownload != nil {
		reader = &downloadProgressReader{reader: resp.Body, total: total, onDownload: onDownload}
	}
	data, err = io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", url, err)
	}
	return data, nil
}

type downloadProgressReader struct {
	reader     io.Reader
	total      int64
	read       int64
	onDownload func(bytesRead, totalBytes int64)
}

func (p *downloadProgressReader) Read(b []byte) (int, error) {
	n, err := p.reader.Read(b)
	if n > 0 {
		p.read += int64(n)
		if p.onDownload != nil {
			p.onDownload(p.read, p.total)
		}
	}
	return n, err
}

// extractBinary locates and reads the sing-box binary from a release tar.gz archive.
func extractBinary(archive []byte, binaryPath string) (data []byte, err error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("gzip open: %w", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar read: %w", err)
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		if name != binaryPath && name != filepath.Base(binaryPath) && !strings.HasSuffix(name, "/sing-box") {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		return io.ReadAll(tr)
	}
	return nil, fmt.Errorf("binary %q not found in archive", binaryPath)
}

// FromBytes installs a binary from raw data with sha256 verification.
func FromBytes(data []byte, destPath, expectedSHA256 string) error {
	return (&Installer{}).FromBytes(data, destPath, expectedSHA256)
}

// FromBytes installs a binary from raw data with sha256 verification.
func (i *Installer) FromBytes(data []byte, destPath, expectedSHA256 string) error {
	return i.fromBytes(data, destPath, expectedSHA256)
}

func (i *Installer) fromBytes(data []byte, destPath, expectedSHA256 string) error {
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != strings.ToLower(expectedSHA256) {
		return fmt.Errorf("checksum mismatch")
	}
	if err := i.mkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return fmt.Errorf("mkdir install dir: %w", err)
	}
	return i.writeFile(destPath, data, 0o755)
}
