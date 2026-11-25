package fsg

import (
	"github.com/orca-zhang/unpack"
	"io"
)

func init() { unpack.RegisterFormat("FSG", FSG{}) }

const (
	FSG_VER_NONE = 0 + iota
	FSG_VER_1
	FSG_VER_2
)

// FSG delegates detection and unpacking to the Rust core.
type FSG struct{}

func (FSG) Name() string           { return "FSG" }
func (FSG) RustFormat() string     { return "FSG" }
func (FSG) Detect(path string) int { return (unpack.RustUnpacker{Format: "FSG"}).Detect(path) }
func (FSG) Unpack(path string) (io.ReaderAt, error) {
	return (unpack.RustUnpacker{Format: "FSG"}).Unpack(path)
}
