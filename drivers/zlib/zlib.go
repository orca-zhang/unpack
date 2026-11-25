// Package zlib decodes ZLIB payloads through the native Rust core.
package zlib

import (
	"github.com/orca-zhang/unpack"
	"io"
)

const (
	ZLIB_VER_NONE = iota
	ZLIB_VER_1
)

type ZLIB struct{}

func init()                         { unpack.RegisterFormat("ZLIB", ZLIB{}) }
func (ZLIB) Name() string           { return "ZLIB" }
func (ZLIB) RustFormat() string     { return "ZLIB" }
func (ZLIB) Detect(path string) int { return (unpack.RustUnpacker{Format: "ZLIB"}).Detect(path) }
func (ZLIB) Unpack(path string) (io.ReaderAt, error) {
	return (unpack.RustUnpacker{Format: "ZLIB"}).Unpack(path)
}
