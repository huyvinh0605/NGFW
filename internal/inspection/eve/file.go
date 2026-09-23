package eve

import (
	"io"
	"os"
)

type OpenedFile interface {
	io.Reader
	io.Seeker
	io.Closer
	Stat() (os.FileInfo, error)
}

type FileSource interface {
	Open(string) (OpenedFile, error)
	Stat(string) (os.FileInfo, error)
	Generation(os.FileInfo) string
}

type OSFileSource struct{}

func (OSFileSource) Open(path string) (OpenedFile, error)  { return os.Open(path) }
func (OSFileSource) Stat(path string) (os.FileInfo, error) { return os.Stat(path) }
func (OSFileSource) Generation(info os.FileInfo) string    { return fileGeneration(info) }
func portableGeneration(info os.FileInfo) string           { return "portable:" + info.Name() }
