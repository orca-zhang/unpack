package winupack

import (
	"encoding/binary"
	"github.com/orca-zhang/unpack/internal/testfixture"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestWinUpackSyntheticRecovery(t *testing.T) {
	data, err := testfixture.PE(".upx0", "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "synthetic.exe")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	packer := WinUpack{}
	if packer.Name() != "WinUpack" || packer.Detect(path) != WINUPACK_VER_1 {
		t.Fatal("WinUpack detection failed")
	}
	reader, err := packer.Unpack(path)
	if err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(io.NewSectionReader(reader, 0, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	p := int(binary.LittleEndian.Uint32(data[60:]))
	original, err := os.ReadFile(filepath.Join(testfixture.Root(), "testdata/upx/pe32.original"))
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(output[p+40:]) != binary.LittleEndian.Uint32(original[p+40:]) {
		t.Fatal("original entry point not restored")
	}
}

func TestWinUpackMissing(t *testing.T) {
	if (WinUpack{}).Detect("nonexistent.exe") != WINUPACK_VER_NONE {
		t.Fatal("missing file detected")
	}
}
