package mpress

import (
	"github.com/orca-zhang/unpack"
	"io"
)

func init() { unpack.RegisterFormat("MPRESS", MPRESS{}) }

const (
	MPRESS_VER_NONE = 0 + iota
	MPRESS_VER_1
	MPRESS_VER_2
)

// MPRESS delegates detection and unpacking to the Rust core.
type MPRESS struct{}

func (MPRESS) Name() string           { return "MPRESS" }
func (MPRESS) RustFormat() string     { return "MPRESS" }
func (MPRESS) Detect(path string) int { return (unpack.RustUnpacker{Format: "MPRESS"}).Detect(path) }
func (MPRESS) Unpack(path string) (io.ReaderAt, error) {
	return (unpack.RustUnpacker{Format: "MPRESS"}).Unpack(path)
}
