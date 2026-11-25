// Package lzma decodes LZMA payloads through the native Rust core.
package lzma

import (
	"github.com/orca-zhang/unpack"
	"io"
)

const (
	LZMA_VER_NONE = iota
	LZMA_VER_1
)

type LZMA struct{}

func init()                         { unpack.RegisterFormat("LZMA", LZMA{}) }
func (LZMA) Name() string           { return "LZMA" }
func (LZMA) RustFormat() string     { return "LZMA" }
func (LZMA) Detect(path string) int { return (unpack.RustUnpacker{Format: "LZMA"}).Detect(path) }
func (LZMA) Unpack(path string) (io.ReaderAt, error) {
	return (unpack.RustUnpacker{Format: "LZMA"}).Unpack(path)
}
