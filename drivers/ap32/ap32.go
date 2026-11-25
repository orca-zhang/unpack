// Package ap32 provides native Rust decompression of aPLib AP32 containers.
package ap32

import (
	"github.com/orca-zhang/unpack"
	"io"
)

const (
	AP32_VER_NONE = iota
	AP32_VER_1
)

type AP32 struct{}

func init()                         { unpack.RegisterFormat("AP32", AP32{}) }
func (AP32) Name() string           { return "AP32" }
func (AP32) RustFormat() string     { return "AP32" }
func (AP32) Detect(path string) int { return (unpack.RustUnpacker{Format: "AP32"}).Detect(path) }
func (AP32) Unpack(path string) (io.ReaderAt, error) {
	return (unpack.RustUnpacker{Format: "AP32"}).Unpack(path)
}
