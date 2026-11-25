// Package pebundle recognizes PEBundle; full unpacking is not implemented.
package pebundle

import (
	"github.com/orca-zhang/unpack"
	"io"
)

const (
	PEBUNDLE_VER_NONE = iota
	PEBUNDLE_VER_1
)

type PEBundle struct{}

func init()                         { unpack.RegisterFormat("PEBundle", PEBundle{}) }
func (PEBundle) Name() string       { return "PEBundle" }
func (PEBundle) RustFormat() string { return "PEBundle" }
func (PEBundle) Detect(path string) int {
	return (unpack.RustUnpacker{Format: "PEBundle"}).Detect(path)
}
func (PEBundle) Unpack(path string) (io.ReaderAt, error) {
	return (unpack.RustUnpacker{Format: "PEBundle"}).Unpack(path)
}
