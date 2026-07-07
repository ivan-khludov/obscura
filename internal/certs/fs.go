package certs

import (
	"io"
	"os"
)

// FileSystem abstracts filesystem operations used by Generator.
type FileSystem interface {
	MkdirAll(path string, perm os.FileMode) error
	OpenFile(path string, flag int, perm os.FileMode) (io.WriteCloser, error)
}

type osFS struct{}

// NewOSFileSystem returns a FileSystem backed by the real operating system.
func NewOSFileSystem() FileSystem {
	return osFS{}
}

func (osFS) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func (osFS) OpenFile(path string, flag int, perm os.FileMode) (io.WriteCloser, error) {
	return os.OpenFile(path, flag, perm)
}
