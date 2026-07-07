package backup

import (
	"archive/tar"
	"io"
	"os"
)

// NewArchiverForTest constructs an archiver with the given filesystem.
func NewArchiverForTest(fs FileSystem) *Archiver {
	return NewArchiver(fs)
}

// NewArchiverForTestWithHeader constructs an archiver with a custom tar header function.
func NewArchiverForTestWithHeader(fs FileSystem, headerFn func(os.FileInfo, string) (*tar.Header, error)) *Archiver {
	return newArchiverWithHeader(fs, headerFn)
}

// WriteArchiveForTest writes sources to w for tests.
func (a *Archiver) WriteArchiveForTest(w io.Writer, sources []string) error {
	return a.writeArchive(w, sources)
}

// ReadArchiveForTest extracts an archive into destDir for tests.
func (a *Archiver) ReadArchiveForTest(r io.Reader, destDir string) error {
	return a.readArchive(r, destDir)
}

// AddToArchiveForTest adds src to the tar writer for tests.
func (a *Archiver) AddToArchiveForTest(tw *tar.Writer, src string) error {
	return a.addToArchive(tw, src)
}

// AddFileForTest adds a single file to the tar writer for tests.
func (a *Archiver) AddFileForTest(tw *tar.Writer, path, name string) error {
	return a.addFile(tw, path, name)
}
