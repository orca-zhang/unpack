package themida

import (
	"github.com/orca-zhang/unpack"
	"io"
)

func init() { unpack.RegisterFormat("Themida", Themida{}) }

const (
	THEMIDA_VER_NONE = 0 + iota
	THEMIDA_VER_1
	THEMIDA_VER_2
)

// Themida delegates detection and unpacking to the Rust core.
type Themida struct{}

func (Themida) Name() string           { return "Themida" }
func (Themida) RustFormat() string     { return "Themida" }
func (Themida) Detect(path string) int { return (unpack.RustUnpacker{Format: "Themida"}).Detect(path) }
func (Themida) Unpack(path string) (io.ReaderAt, error) {
	return (unpack.RustUnpacker{Format: "Themida"}).Unpack(path)
}
