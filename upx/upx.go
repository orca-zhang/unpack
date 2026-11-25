package upx

import (
	"github.com/orca-zhang/unpack"
	"io"
)

func init() { unpack.RegisterFormat("UPX", UPX{}) }

const (
	UPX_VER_NONE = 0 + iota
	UPX_VER_1
	UPX_VER_2
	UPX_VER_3
	UPX_VER_4
)

// UPX delegates detection and unpacking to the Rust core.
type UPX struct{}

func (UPX) Name() string           { return "UPX" }
func (UPX) RustFormat() string     { return "UPX" }
func (UPX) Detect(path string) int { return (unpack.RustUnpacker{Format: "UPX"}).Detect(path) }
func (UPX) Unpack(path string) (io.ReaderAt, error) {
	return (unpack.RustUnpacker{Format: "UPX"}).Unpack(path)
}

type UPXHeader struct {
	Signature       [4]byte // "UPX!"
	VersionMajor    uint8
	VersionMinor    uint8
	VersionRevision uint8
	Format          uint8
	Method          uint32
	OriginalSize    uint32
	CompressedSize  uint32
	Filter          uint32
	FilterCTO       uint32
	HeaderChecksum  uint32
	FileChecksum    uint32
}
