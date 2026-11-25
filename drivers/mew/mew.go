// Package mew recognizes MEW; full unpacking is not implemented.
package mew

import (
	"github.com/orca-zhang/unpack"
	"io"
)

const (
	MEW_VER_NONE = iota
	MEW_VER_1
)

type MEW struct{}

func init()                        { unpack.RegisterFormat("MEW", MEW{}) }
func (MEW) Name() string           { return "MEW" }
func (MEW) RustFormat() string     { return "MEW" }
func (MEW) Detect(path string) int { return (unpack.RustUnpacker{Format: "MEW"}).Detect(path) }
func (MEW) Unpack(path string) (io.ReaderAt, error) {
	return (unpack.RustUnpacker{Format: "MEW"}).Unpack(path)
}
