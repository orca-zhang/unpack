// Package vmprotect recognizes VMProtect; full unpacking is not implemented.
package vmprotect

import (
	"github.com/orca-zhang/unpack"
	"io"
)

const (
	VMPROTECT_VER_NONE = iota
	VMPROTECT_VER_1
)

type VMProtect struct{}

func init()                          { unpack.RegisterFormat("VMProtect", VMProtect{}) }
func (VMProtect) Name() string       { return "VMProtect" }
func (VMProtect) RustFormat() string { return "VMProtect" }
func (VMProtect) Detect(path string) int {
	return (unpack.RustUnpacker{Format: "VMProtect"}).Detect(path)
}
func (VMProtect) Unpack(path string) (io.ReaderAt, error) {
	return (unpack.RustUnpacker{Format: "VMProtect"}).Unpack(path)
}
