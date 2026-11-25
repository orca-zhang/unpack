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
	_ "github.com/orca-zhang/unpack/drivers/ap32"
	_ "github.com/orca-zhang/unpack/drivers/armadillo"
	_ "github.com/orca-zhang/unpack/drivers/aspack"
	_ "github.com/orca-zhang/unpack/drivers/enigma"
	_ "github.com/orca-zhang/unpack/drivers/fsg"
	_ "github.com/orca-zhang/unpack/drivers/gzip"
	_ "github.com/orca-zhang/unpack/drivers/lzma"
	_ "github.com/orca-zhang/unpack/drivers/mew"
	_ "github.com/orca-zhang/unpack/drivers/mpress"
	_ "github.com/orca-zhang/unpack/drivers/nspack"
	_ "github.com/orca-zhang/unpack/drivers/pebundle"
	_ "github.com/orca-zhang/unpack/drivers/pecompact"
	_ "github.com/orca-zhang/unpack/drivers/pelock"
	_ "github.com/orca-zhang/unpack/drivers/pespin"
	_ "github.com/orca-zhang/unpack/drivers/petite"
	_ "github.com/orca-zhang/unpack/drivers/themida"
	_ "github.com/orca-zhang/unpack/drivers/upx"
	_ "github.com/orca-zhang/unpack/drivers/vmprotect"
	_ "github.com/orca-zhang/unpack/drivers/winupack"
	_ "github.com/orca-zhang/unpack/drivers/xz"
	_ "github.com/orca-zhang/unpack/drivers/yoda"
	_ "github.com/orca-zhang/unpack/drivers/zlib"
)
