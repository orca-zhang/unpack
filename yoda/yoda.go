// Package yoda recognizes Yoda; full unpacking is not implemented.
package yoda

import (
	"github.com/orca-zhang/unpack"
	"io"
)

const (
	YODA_VER_NONE = iota
	YODA_VER_1
)

type Yoda struct{}

func init()                         { unpack.RegisterFormat("Yoda", Yoda{}) }
func (Yoda) Name() string           { return "Yoda" }
func (Yoda) RustFormat() string     { return "Yoda" }
func (Yoda) Detect(path string) int { return (unpack.RustUnpacker{Format: "Yoda"}).Detect(path) }
func (Yoda) Unpack(path string) (io.ReaderAt, error) {
	return (unpack.RustUnpacker{Format: "Yoda"}).Unpack(path)
}
