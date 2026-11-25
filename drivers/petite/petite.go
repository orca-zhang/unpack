package petite

import (
	"github.com/orca-zhang/unpack"
	"io"
)

func init() { unpack.RegisterFormat("Petite", Petite{}) }

const (
	PETITE_VER_NONE = 0 + iota
	PETITE_VER_1
	PETITE_VER_2
	PETITE_VER_23
)

// Petite delegates detection and unpacking to the Rust core.
type Petite struct{}

func (Petite) Name() string           { return "Petite" }
func (Petite) RustFormat() string     { return "Petite" }
func (Petite) Detect(path string) int { return (unpack.RustUnpacker{Format: "Petite"}).Detect(path) }
func (Petite) Unpack(path string) (io.ReaderAt, error) {
	return (unpack.RustUnpacker{Format: "Petite"}).Unpack(path)
}
