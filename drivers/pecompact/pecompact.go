package pecompact

import (
	"github.com/orca-zhang/unpack"
	"io"
)

func init() { unpack.RegisterFormat("PECompact", PECompact{}) }

const (
	PECOMPACT_VER_NONE = 0 + iota
	PECOMPACT_VER_1
	PECOMPACT_VER_2
	PECOMPACT_VER_3
)

// PECompact delegates detection and unpacking to the Rust core.
type PECompact struct{}

func (PECompact) Name() string       { return "PECompact" }
func (PECompact) RustFormat() string { return "PECompact" }
func (PECompact) Detect(path string) int {
	return (unpack.RustUnpacker{Format: "PECompact"}).Detect(path)
}
func (PECompact) Unpack(path string) (io.ReaderAt, error) {
	return (unpack.RustUnpacker{Format: "PECompact"}).Unpack(path)
}
