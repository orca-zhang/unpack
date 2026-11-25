// Package drivers provides a convenient way to import all supported packers at once.
// Importing this package will automatically register all packers with the unpack library.
//
// Usage:
//
//	import _ "github.com/orca-zhang/unpack/drivers"
//
// This will register all supported packers:
//   - UPX
//   - AP32 (native aPLib container decompression)
//   - GZIP, ZLIB, XZ, LZMA (native payload decoding; LZMA requires explicit selection)
//   - ASPack
//   - FSG
//   - WinUpack
//   - Petite
//   - PESpin
//   - Armadillo
//   - Themida
//   - PECompact
//   - NSPack
//   - MPRESS
//   - VMProtect, Enigma, MEW, PELock, PEBundle, Yoda (detection only)
package drivers

import (
	_ "github.com/orca-zhang/unpack/ap32"
	_ "github.com/orca-zhang/unpack/enigma"
	_ "github.com/orca-zhang/unpack/gzip"
	_ "github.com/orca-zhang/unpack/lzma"
	_ "github.com/orca-zhang/unpack/mew"
	_ "github.com/orca-zhang/unpack/pebundle"
	_ "github.com/orca-zhang/unpack/pelock"
	_ "github.com/orca-zhang/unpack/vmprotect"
	_ "github.com/orca-zhang/unpack/xz"
	_ "github.com/orca-zhang/unpack/yoda"
	_ "github.com/orca-zhang/unpack/zlib"
	// Import all packer packages to trigger their init() functions
	// which register them with the unpack library
	_ "github.com/orca-zhang/unpack/armadillo"
	_ "github.com/orca-zhang/unpack/aspack"
	_ "github.com/orca-zhang/unpack/fsg"
	_ "github.com/orca-zhang/unpack/mpress"
	_ "github.com/orca-zhang/unpack/nspack"
	_ "github.com/orca-zhang/unpack/pecompact"
	_ "github.com/orca-zhang/unpack/pespin"
	_ "github.com/orca-zhang/unpack/petite"
	_ "github.com/orca-zhang/unpack/themida"
	_ "github.com/orca-zhang/unpack/upx"
	_ "github.com/orca-zhang/unpack/winupack"
)
