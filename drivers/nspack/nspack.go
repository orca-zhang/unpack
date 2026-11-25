package nspack

import (
	"github.com/orca-zhang/unpack"
	"io"
)

func init() { unpack.RegisterFormat("NSPack", NSPack{}) }

const (
	NSPACK_VER_NONE = 0 + iota
	NSPACK_VER_1
	NSPACK_VER_2
)

// NSPack delegates detection and unpacking to the Rust core.
type NSPack struct{}

func (NSPack) Name() string           { return "NSPack" }
func (NSPack) RustFormat() string     { return "NSPack" }
func (NSPack) Detect(path string) int { return (unpack.RustUnpacker{Format: "NSPack"}).Detect(path) }
func (NSPack) Unpack(path string) (io.ReaderAt, error) {
	return (unpack.RustUnpacker{Format: "NSPack"}).Unpack(path)
}
