package backup

import (
	"io"
	"os"
	"path/filepath"
)

// ReadStatFile is a readable file handle with metadata.
type ReadStatFile interface {
	io.Reader
	io.Closer
	Stat() (os.FileInfo, error)
}

// FileSystem abstracts filesystem operations used by Archiver.
type FileSystem interface {
	Create(name string) (io.WriteCloser, error)
	Open(name string) (ReadStatFile, error)
	OpenFile(path string, flag int, perm os.FileMode) (io.WriteCloser, error)
	Stat(name string) (os.FileInfo, error)
	MkdirAll(path string, perm os.FileMode) error
	Walk(root string, fn filepath.WalkFunc) error
	Rel(basepath, targpath string) (string, error)
}

type osFS struct{}

// NewOSFileSystem returns a FileSystem backed by the real operating system.
func NewOSFileSystem() FileSystem {
	return osFS{}
}

func (osFS) Create(name string) (io.WriteCloser, error) {
	return os.Create(name)
}

func (osFS) Open(name string) (ReadStatFile, error) {
	return os.Open(name)
}

func (osFS) OpenFile(path string, flag int, perm os.FileMode) (io.WriteCloser, error) {
	return os.OpenFile(path, flag, perm)
}

func (osFS) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

func (osFS) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func (osFS) Walk(root string, fn filepath.WalkFunc) error {
	return filepath.Walk(root, fn)
}

func (osFS) Rel(basepath, targpath string) (string, error) {
	return filepath.Rel(basepath, targpath)
}
