package aspack

import (
	"github.com/orca-zhang/unpack"
	"io"
)

func init() { unpack.RegisterFormat("ASPack", ASPack{}) }

const (
	ASPACK_EP_OFFSET_212   = (58 + 0x70e)
	ASPACK_EP_OFFSET_OTHER = (58 + 0x76a)
	ASPACK_EP_OFFSET_242   = (58 + 0x776)

	ASPACK_EPBUFF_OFFSET_21    = (0x4fd)
	ASPACK_EPBUFF_OFFSET_212   = (0x3b9)
	ASPACK_EPBUFF_OFFSET_OTHER = (0x41f)
	ASPACK_EPBUFF_OFFSET_242   = (0x42B)

	ASPACK_BLOCKS_OFFSET_212   = 0x57c
	ASPACK_BLOCKS_OFFSET_OTHER = 0x5d8
	ASPACK_BLOCKS_OFFSET_242   = 0x5e4

	ASPACK_STR_INIT_MLT_OFFSET_212   = 0x70e
	ASPACK_STR_INIT_MLT_OFFSET_OTHER = 0x76a
	ASPACK_STR_INIT_MLT_OFFSET_242   = 0x776

	ASPACK_COMP_BLOCK_OFFSET_212   = 0x6d6
	ASPACK_COMP_BLOCK_OFFSET_OTHER = 0x732
	ASPACK_COMP_BLOCK_OFFSET_242   = 0x73e

	ASPACK_WRKBUF_OFFSET_212   = 0x148
	ASPACK_WRKBUF_OFFSET_OTHER = 0x13a
	ASPACK_WRKBUF_OFFSET_242   = 0x148
)

const (
	ASPACK_VER_NONE = 0 + iota
	ASPACK_VER_21
	ASPACK_VER_212
	ASPACK_VER_OTHER
	ASPACK_VER_242
)

// ASPack delegates detection and unpacking to the Rust core.
type ASPack struct{}

func (ASPack) Name() string           { return "ASPack" }
func (ASPack) RustFormat() string     { return "ASPack" }
func (ASPack) Detect(path string) int { return (unpack.RustUnpacker{Format: "ASPack"}).Detect(path) }
func (ASPack) Unpack(path string) (io.ReaderAt, error) {
	return (unpack.RustUnpacker{Format: "ASPack"}).Unpack(path)
}

type CompressedBlock struct {
	SourceRVA        uint32 // Source RVA in compressed data
	DestRVA          uint32 // Destination RVA in decompressed data
	CompressedSize   uint32 // Compressed size
	DecompressedSize uint32 // Decompressed size
}
