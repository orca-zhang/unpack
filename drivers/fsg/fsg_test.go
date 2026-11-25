package fsg

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/orca-zhang/unpack/internal/testfixture"
)

func TestVersionAdapters(t *testing.T) {
	packer := FSG{}
	for _, version := range []int{1, 2} {
		for _, shift := range []int{0, 29} {
			name := fmt.Sprintf("fsg-id%d-entry%d", version, shift)
			t.Run(name, func(t *testing.T) {
				base := filepath.Join(testfixture.Root(), "testdata/pe-versions", name)
				if packer.Name() != "FSG" || packer.Detect(base+".bin") != version {
					t.Fatal("version detection failed")
				}
				reader, err := packer.Unpack(base + ".bin")
				if err != nil {
					t.Fatal(err)
				}
				got, err := io.ReadAll(io.NewSectionReader(reader, 0, 1<<20))
				if err != nil {
					t.Fatal(err)
				}
				want, err := os.ReadFile(base + ".recovered")
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want) {
					t.Fatal("SDK output differs from golden")
				}
			})
		}
	}
	if packer.Detect("nonexistent.exe") != 0 {
		t.Fatal("missing input detected")
	}
	if _, err := packer.Unpack("nonexistent.exe"); err == nil {
		t.Fatal("missing input accepted")
	}
}
