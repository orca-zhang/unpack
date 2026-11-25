package aspack

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/orca-zhang/unpack/internal/testfixture"
)

func TestASPackLayoutAdapters(t *testing.T) {
	packer := ASPack{}
	for _, test := range []struct {
		profile string
		version int
	}{
		{"2.1", ASPACK_VER_21}, {"2.12", ASPACK_VER_212}, {"other-0x41f", ASPACK_VER_OTHER}, {"2.42", ASPACK_VER_242},
	} {
		t.Run(test.profile, func(t *testing.T) {
			for _, variant := range []string{"basic", "shifted-entry", "reordered-sections", "preserve-imports", "no-imports"} {
				base := filepath.Join(testfixture.Root(), "testdata/pe-versions", "aspack-"+test.profile+"-"+variant)
				if got := packer.Detect(base + ".bin"); got != test.version {
					t.Fatalf("%s version: got %d, want %d", variant, got, test.version)
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
					t.Fatalf("%s SDK result differs from golden", variant)
				}
			}
		})
	}
	if packer.Detect(filepath.Join(testfixture.Root(), "testdata/aspack/aspack_test.exe")) != ASPACK_VER_21 {
		t.Fatal("existing 2.1 fixture regressed")
	}
}
