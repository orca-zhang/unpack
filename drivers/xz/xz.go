// Package xz decodes XZ payloads through the native Rust core.
package xz

import (
	"github.com/orca-zhang/unpack"
	"io"
)

const (
	XZ_VER_NONE = iota
	XZ_VER_1
)

type XZ struct{}

func init()                       { unpack.RegisterFormat("XZ", XZ{}) }
func (XZ) Name() string           { return "XZ" }
func (XZ) RustFormat() string     { return "XZ" }
func (XZ) Detect(path string) int { return (unpack.RustUnpacker{Format: "XZ"}).Detect(path) }
func (XZ) Unpack(path string) (io.ReaderAt, error) {
	return (unpack.RustUnpacker{Format: "XZ"}).Unpack(path)
}
