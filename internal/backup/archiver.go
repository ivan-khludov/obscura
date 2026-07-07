package backup

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Archiver creates and restores obscura state archives.
type Archiver struct {
	fs       FileSystem
	headerFn func(os.FileInfo, string) (*tar.Header, error)
}

// NewArchiver returns an Archiver that uses the given filesystem.
func NewArchiver(fs FileSystem) *Archiver {
	return &Archiver{
		fs:       fs,
		headerFn: tar.FileInfoHeader,
	}
}

func newArchiverWithHeader(fs FileSystem, headerFn func(os.FileInfo, string) (*tar.Header, error)) *Archiver {
	return &Archiver{
		fs:       fs,
		headerFn: headerFn,
	}
}

// Create builds a gzip tar archive of the given paths into destPath.
func (a *Archiver) Create(destPath string, sources []string) (err error) {
	f, err := a.fs.Create(destPath)
	if err != nil {
		return fmt.Errorf("create backup: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close backup: %w", cerr)
		}
	}()
	return a.writeArchive(f, sources)
}

// Restore extracts a backup archive into destDir.
func (a *Archiver) Restore(archivePath, destDir string) (err error) {
	f, err := a.fs.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open backup: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close backup: %w", cerr)
		}
	}()
	return a.readArchive(f, destDir)
}

func (a *Archiver) writeArchive(w io.Writer, sources []string) (err error) {
	gw := gzip.NewWriter(w)
	defer func() {
		if cerr := gw.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close gzip: %w", cerr)
		}
	}()
	tw := tar.NewWriter(gw)
	defer func() {
		if cerr := tw.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close tar: %w", cerr)
		}
	}()
	for _, src := range sources {
		if err := a.addToArchive(tw, src); err != nil {
			return err
		}
	}
	return nil
}

func (a *Archiver) addToArchive(tw *tar.Writer, src string) error {
	info, err := a.fs.Stat(src)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat %s: %w", src, err)
	}
	if !info.IsDir() {
		return a.addFile(tw, src, filepath.Base(src))
	}
	return a.fs.Walk(src, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		rel, err := a.fs.Rel(src, path)
		if err != nil {
			return err
		}
		name := filepath.Join(filepath.Base(src), rel)
		return a.addFile(tw, path, name)
	})
}

func (a *Archiver) addFile(tw *tar.Writer, path, name string) (err error) {
	f, err := a.fs.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	hdr, err := a.headerFn(info, name)
	if err != nil {
		return err
	}
	hdr.Name = name
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

func (a *Archiver) readArchive(r io.Reader, destDir string) (err error) {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer func() {
		if cerr := gr.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close gzip: %w", cerr)
		}
	}()
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}
		target := filepath.Join(destDir, hdr.Name)
		if err := a.fs.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		out, err := a.fs.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, tr); err != nil {
			if cerr := out.Close(); cerr != nil {
				return fmt.Errorf("copy %s: %w (close: %v)", hdr.Name, err, cerr)
			}
			return err
		}
		if err := out.Close(); err != nil {
			return err
		}
	}
}
