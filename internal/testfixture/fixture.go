// Package testfixture creates synthetic PE stubs for parser and recovery tests.
// These are not real packer outputs; real UPX samples live in testdata/upx.
package testfixture

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
)

func Root() string {
	_, path, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(path), "../.."))
}

func PE(section, marker string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(Root(), "testdata/upx/pe32.original"))
	if err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	p := int(le.Uint32(data[60:]))
	optional := p + 24
	originalEP := le.Uint32(data[optional+16:])
	table := optional + int(le.Uint16(data[p+20:]))
	// The last section becomes a synthetic packer stub; keep the original code section.
	stub := table + (int(le.Uint16(data[p+6:]))-1)*40
	clear(data[stub : stub+8])
	copy(data[stub:stub+8], section)
	rva := le.Uint32(data[stub+12:])
	off := int(le.Uint32(data[stub+20:]))
	le.PutUint32(data[optional+16:], rva)
	le.PutUint32(data[stub+36:], 0xe0000060)
	data[off] = 0xe9
	le.PutUint32(data[off+1:], uint32(int64(originalEP)-int64(rva)-5))
	if section == ".aspack" {
		copy(data[off+0x4fd:], []byte{0x68, 0, 0, 0, 0, 0xc3})
		le.PutUint32(data[off+0x4f4:], originalEP)
	}
	if marker != "" {
		copy(data[len(data)-len(marker):], marker)
	}
	return data, nil
}
