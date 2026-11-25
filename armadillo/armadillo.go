package armadillo

import (
	"github.com/orca-zhang/unpack"
	"io"
)

func init() { unpack.RegisterFormat("Armadillo", Armadillo{}) }

const (
	ARMADILLO_VER_NONE = 0 + iota
	ARMADILLO_VER_1
	ARMADILLO_VER_2
	ARMADILLO_VER_3
)

// Armadillo delegates detection and unpacking to the Rust core.
type Armadillo struct{}

func (Armadillo) Name() string       { return "Armadillo" }
func (Armadillo) RustFormat() string { return "Armadillo" }
func (Armadillo) Detect(path string) int {
	return (unpack.RustUnpacker{Format: "Armadillo"}).Detect(path)
}
func (Armadillo) Unpack(path string) (io.ReaderAt, error) {
	return (unpack.RustUnpacker{Format: "Armadillo"}).Unpack(path)
}
