package winupack

import (
	"github.com/orca-zhang/unpack"
	"io"
)

func init() { unpack.RegisterFormat("WinUpack", WinUpack{}) }

const (
	WINUPACK_VER_NONE = 0 + iota
	WINUPACK_VER_1
	WINUPACK_VER_2
)

// WinUpack delegates detection and unpacking to the Rust core.
type WinUpack struct{}

func (WinUpack) Name() string       { return "WinUpack" }
func (WinUpack) RustFormat() string { return "WinUpack" }
func (WinUpack) Detect(path string) int {
	return (unpack.RustUnpacker{Format: "WinUpack"}).Detect(path)
}
func (WinUpack) Unpack(path string) (io.ReaderAt, error) {
	return (unpack.RustUnpacker{Format: "WinUpack"}).Unpack(path)
}
