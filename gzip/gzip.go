// Package gzip decodes GZIP payloads through the native Rust core.
package gzip

import (
	"github.com/orca-zhang/unpack"
	"io"
)

const (
	GZIP_VER_NONE = iota
	GZIP_VER_1
)

type GZIP struct{}

func init()                         { unpack.RegisterFormat("GZIP", GZIP{}) }
func (GZIP) Name() string           { return "GZIP" }
func (GZIP) RustFormat() string     { return "GZIP" }
func (GZIP) Detect(path string) int { return (unpack.RustUnpacker{Format: "GZIP"}).Detect(path) }
func (GZIP) Unpack(path string) (io.ReaderAt, error) {
	return (unpack.RustUnpacker{Format: "GZIP"}).Unpack(path)
}
