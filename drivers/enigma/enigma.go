// Package enigma recognizes Enigma; full unpacking is not implemented.
package enigma

import (
	"github.com/orca-zhang/unpack"
	"io"
)

const (
	ENIGMA_VER_NONE = iota
	ENIGMA_VER_1
)

type Enigma struct{}

func init()                           { unpack.RegisterFormat("Enigma", Enigma{}) }
func (Enigma) Name() string           { return "Enigma" }
func (Enigma) RustFormat() string     { return "Enigma" }
func (Enigma) Detect(path string) int { return (unpack.RustUnpacker{Format: "Enigma"}).Detect(path) }
func (Enigma) Unpack(path string) (io.ReaderAt, error) {
	return (unpack.RustUnpacker{Format: "Enigma"}).Unpack(path)
}
