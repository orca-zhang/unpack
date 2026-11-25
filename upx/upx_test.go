package upx

import (
	"bytes"
	"github.com/orca-zhang/unpack/internal/testfixture"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUPXRealSamples(t *testing.T) {
	for _, name := range []string{"pe32", "pe32-lzma", "pe32-filter", "pe64", "elf64", "elf32", "elf-arm64", "macho64"} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(testfixture.Root(), "testdata/upx")
			packer := UPX{}
			if packer.Name() != "UPX" {
				t.Fatal(packer.Name())
			}
			if packer.Detect(filepath.Join(dir, name+".packed")) != UPX_VER_1 {
				t.Fatal("UPX not detected")
			}
			originalName := name
			if strings.HasPrefix(name, "pe32-") {
				originalName = "pe32"
			}
			if packer.Detect(filepath.Join(dir, originalName+".original")) != UPX_VER_NONE {
				t.Fatal("false positive on original")
			}
			reader, err := packer.Unpack(filepath.Join(dir, name+".packed"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(io.NewSectionReader(reader, 0, 1<<20))
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join(dir, name+".unpacked"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("output differs from official UPX decoder")
			}
		})
	}
}

func TestUPXInvalidInputs(t *testing.T) {
	if (UPX{}).Detect("nonexistent.exe") != UPX_VER_NONE {
		t.Fatal("missing file detected")
	}
	path := filepath.Join(t.TempDir(), "fake.exe")
	if err := os.WriteFile(path, []byte("UPX!"), 0600); err != nil {
		t.Fatal(err)
	}
	if (UPX{}).Detect(path) != UPX_VER_NONE {
		t.Fatal("non-executable signature detected")
	}
	if _, err := (UPX{}).Unpack(path); err == nil {
		t.Fatal("accepted invalid executable")
	}
}

func BenchmarkUPXDetect(b *testing.B) {
	path := filepath.Join(testfixture.Root(), "testdata/upx/pe32.packed")
	for i := 0; i < b.N; i++ {
		(UPX{}).Detect(path)
	}
}
