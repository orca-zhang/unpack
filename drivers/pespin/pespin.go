package pespin

import (
	"github.com/orca-zhang/unpack"
	"io"
)

func init() { unpack.RegisterFormat("PESpin", PESpin{}) }

const (
	PESPIN_VER_NONE = 0 + iota
	PESPIN_VER_1
	PESPIN_VER_2
)

// PESpin delegates detection and unpacking to the Rust core.
type PESpin struct{}

func (PESpin) Name() string           { return "PESpin" }
func (PESpin) RustFormat() string     { return "PESpin" }
func (PESpin) Detect(path string) int { return (unpack.RustUnpacker{Format: "PESpin"}).Detect(path) }
func (PESpin) Unpack(path string) (io.ReaderAt, error) {
	return (unpack.RustUnpacker{Format: "PESpin"}).Unpack(path)
}
