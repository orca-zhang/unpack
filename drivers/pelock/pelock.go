// Package pelock recognizes PELock; full unpacking is not implemented.
package pelock

import (
	"github.com/orca-zhang/unpack"
	"io"
)

const (
	PELOCK_VER_NONE = iota
	PELOCK_VER_1
)

type PELock struct{}

func init()                           { unpack.RegisterFormat("PELock", PELock{}) }
func (PELock) Name() string           { return "PELock" }
func (PELock) RustFormat() string     { return "PELock" }
func (PELock) Detect(path string) int { return (unpack.RustUnpacker{Format: "PELock"}).Detect(path) }
func (PELock) Unpack(path string) (io.ReaderAt, error) {
	return (unpack.RustUnpacker{Format: "PELock"}).Unpack(path)
}
