package fsg

import (
	"encoding/binary"
	"github.com/orca-zhang/unpack/internal/testfixture"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestFSGSyntheticRecovery(t *testing.T) {
	data, err := testfixture.PE(".packed", "FSG!")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "synthetic.exe")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	packer := FSG{}
	if packer.Name() != "FSG" || packer.Detect(path) != FSG_VER_1 {
		t.Fatal("FSG detection failed")
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
	before := binary.LittleEndian.Uint32(data[p+40:])
	after := binary.LittleEndian.Uint32(output[p+40:])
	original, err := os.ReadFile(filepath.Join(testfixture.Root(), "testdata/upx/pe32.original"))
	if err != nil {
		t.Fatal(err)
	}
	want := binary.LittleEndian.Uint32(original[p+40:])
	if before == after || after != want {
		t.Fatalf("entry point: %x -> %x", before, after)
	}
}

func TestFSGMissing(t *testing.T) {
	if (FSG{}).Detect("nonexistent.exe") != FSG_VER_NONE {
		t.Fatal("missing file detected")
	}
	if _, err := (FSG{}).Unpack("nonexistent.exe"); err == nil {
		t.Fatal("missing file accepted")
	}
}
