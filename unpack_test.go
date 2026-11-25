package unpack

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/orca-zhang/unpack/internal/testfixture"
	"io"
	"os"
	"path/filepath"
	"testing"
)

var builtins = []string{"GZIP", "ZLIB", "XZ", "LZMA", "AP32", "UPX", "ASPack", "FSG", "WinUpack", "Petite", "PESpin", "Armadillo", "Themida", "PECompact", "NSPack", "MPRESS", "VMProtect", "Enigma", "MEW", "PELock", "PEBundle", "Yoda"}

func registry(t *testing.T, names []string) {
	t.Helper()
	previous := map[string]Unpacker{}
	ups.Range(func(k, v interface{}) bool { previous[k.(string)] = v.(Unpacker); ups.Delete(k); return true })
	for _, name := range names {
		RegisterFormat(name, RustUnpacker{Format: name})
	}
	t.Cleanup(func() {
		ups.Range(func(k, v interface{}) bool { ups.Delete(k); return true })
		for name, up := range previous {
			RegisterFormat(name, up)
		}
	})
}
func contents(t *testing.T, reader io.ReaderAt) []byte {
	t.Helper()
	data, err := io.ReadAll(io.NewSectionReader(reader, 0, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func sample(name string) string { return filepath.Join(testfixture.Root(), "testdata/upx", name) }

func TestGoSDKRealUPX(t *testing.T) {
	registry(t, builtins)
	for _, name := range []string{"pe32", "pe32-lzma", "pe32-filter", "pe64", "elf64", "elf32", "elf-arm64", "macho64"} {
		t.Run(name, func(t *testing.T) {
			input := sample(name + ".packed")
			up, version := DetectFormat(input)
			if up == nil || up.Name() != "UPX" || version != 1 {
				t.Fatal("detection failed")
			}
			info, err := Inspect(input)
			if err != nil || info.Support != "unpack" {
				t.Fatalf("Inspect: %v %v", info, err)
			}
			result, err := UnpackAll(input)
			if err != nil {
				t.Fatal(err)
			}
			golden, err := os.ReadFile(sample(name + ".unpacked"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(contents(t, result.ReaderAt), golden) || len(result.History) != 1 || len(result.Warnings) != 0 {
				t.Fatal("result differs from official decoder")
			}
		})
	}
}

func TestGoSDKRegistrationAndLimits(t *testing.T) {
	registry(t, nil)
	input := sample("pe32.packed")
	result, err := UnpackAll(input)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(input)
	if len(result.History) != 0 || !bytes.Equal(before, contents(t, result.ReaderAt)) {
		t.Fatal("unregistered driver was used")
	}
	RegisterFormat("UPX", RustUnpacker{Format: "UPX"})
	for _, options := range []Options{{MaxDepth: -1}, {MaxSize: -1}, {MaxSize: 1 << 31}, {MaxSize: 4}} {
		if _, err := UnpackWithOptions(context.Background(), input, options); err == nil {
			t.Fatal("invalid size/depth accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := UnpackWithOptions(ctx, input, Options{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
}

func TestGoSDKRegistrationAlias(t *testing.T) {
	registry(t, nil)
	RegisterFormat("custom-registration-key", RustUnpacker{Format: "UPX"})
	up, version := DetectFormat(sample("pe32.packed"))
	if up == nil || up.Name() != "UPX" || version != 1 {
		t.Fatal("registration alias lost")
	}
	result, err := UnpackAll(sample("pe32.packed"))
	if err != nil || len(result.History) != 1 {
		t.Fatalf("alias unpack: %v %v", result, err)
	}
}

func TestGoSDKWithoutCLI(t *testing.T) {
	registry(t, builtins)
	t.Setenv("UNPACK_RUST_BIN", filepath.Join(t.TempDir(), "nonexistent-cli"))
	t.Setenv("PATH", t.TempDir())
	if _, err := UnpackAll("missing.exe"); err == nil {
		t.Fatal("missing input accepted")
	}
	path := filepath.Join(testfixture.Root(), "testdata/aplib/tokens.ap32")
	result, err := UnpackAll(path)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := os.ReadFile(filepath.Join(testfixture.Root(), "testdata/aplib/tokens.unpacked"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(contents(t, result.ReaderAt), expected) {
		t.Fatal("embedded Rust returned different bytes")
	}
	info, err := Inspect(path)
	if err != nil || info == nil || info.Name != "AP32" {
		t.Fatalf("native detection: %v %v", info, err)
	}
}

type removedPlugin struct{}

func (removedPlugin) Name() string                       { panic("Go plugin executed") }
func (removedPlugin) Detect(string) int                  { panic("Go detector executed") }
func (removedPlugin) Unpack(string) (io.ReaderAt, error) { panic("Go unpacker executed") }

func TestGoImplementationsAreRejected(t *testing.T) {
	registry(t, nil)
	RegisterFormat("removed", removedPlugin{})
	_, err := UnpackAll(sample("pe32.packed"))
	var coreErr *Error
	if !errors.As(err, &coreErr) || coreErr.Code != "unsupported" {
		t.Fatalf("Go plugin accepted: %v", err)
	}
	if up, _ := DetectFormat(sample("pe32.packed")); up != nil {
		t.Fatal("Go detector accepted")
	}
}

func TestGoSDKNativeAP32AndUPXChain(t *testing.T) {
	registry(t, builtins)
	dir := filepath.Join(testfixture.Root(), "testdata/aplib")
	for _, name := range []string{"tokens", "offsets", "pe32", "nested", "upx"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".ap32")
			info, err := Inspect(path)
			if err != nil || info.Name != "AP32" || info.Support != "unpack" {
				t.Fatalf("AP32 detection: %v %v", info, err)
			}
			if name != "upx" {
				t.Setenv("UNPACK_UPX", filepath.Join(t.TempDir(), "no-backend-needed"))
			}
			result, err := UnpackAll(path)
			if err != nil {
				t.Fatal(err)
			}
			goldenPath := filepath.Join(dir, name+".unpacked")
			if name == "nested" {
				goldenPath = filepath.Join(dir, "tokens.unpacked")
			}
			if name == "upx" {
				goldenPath = sample("pe32.unpacked")
			}
			expected, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(contents(t, result.ReaderAt), expected) {
				t.Fatal("AP32 output differs from independently verified fixture")
			}
			if name == "upx" && (len(result.History) != 2 || result.History[1].PackerName != "UPX") {
				t.Fatal("AP32/UPX history missing")
			}
		})
	}
}

func TestGoSDKPayloads(t *testing.T) {
	registry(t, builtins)
	dir := filepath.Join(testfixture.Root(), "testdata/payloads")
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Samples []struct {
			Name, Format, Packed, Unpacked string
			History                        []string
			Explicit                       bool
		}
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Samples) != 20 {
		t.Fatal("missing payload fixtures")
	}
	for _, s := range manifest.Samples {
		t.Run(s.Name, func(t *testing.T) {
			input := filepath.Join(dir, s.Packed)
			if s.Name != "gzip-xz-upx" {
				t.Setenv("UNPACK_UPX", filepath.Join(t.TempDir(), "no-backend-needed"))
			}
			var reader io.ReaderAt
			if s.Explicit {
				reader, err = (RustUnpacker{Format: s.Format}).Unpack(input)
			} else {
				result, callErr := UnpackAll(input)
				err = callErr
				if err == nil {
					reader = result.ReaderAt
					if len(result.History) != len(s.History) {
						t.Fatal("wrong layer count")
					}
					for i, layer := range result.History {
						if layer.PackerName != s.History[i] {
							t.Fatal("wrong layer history")
						}
					}
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			expected, err := os.ReadFile(filepath.Join(dir, s.Unpacked))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(contents(t, reader), expected) {
				t.Fatal("payload differs from independent Python codec output")
			}
		})
	}
}

func TestExplicitFormatWithoutRegistration(t *testing.T) {
	registry(t, nil)
	path := filepath.Join(testfixture.Root(), "testdata/payloads/text-lzma.packed")
	result, err := UnpackWithOptions(context.Background(), path, Options{Format: "LZMA"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.History) != 1 || result.History[0].PackerName != "LZMA" {
		t.Fatal("explicit format did not record one layer")
	}
	_, err = UnpackWithOptions(context.Background(), path, Options{Format: "unknown"})
	if err == nil {
		t.Fatal("unknown format accepted")
	}
}

func TestGoSDKVersionMatrix(t *testing.T) {
	registry(t, builtins)
	data, err := os.ReadFile("testdata/pe-versions/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Cases []struct {
			Name, Family, Input string
			Version             int
			Detected            bool
			DetectError         *string `json:"detect_error"`
			RecoveryError       *string `json:"recovery_error"`
			Output              string
		}
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Cases) != 105 {
		t.Fatal("version cases missing")
	}
	for _, c := range manifest.Cases {
		t.Run(c.Name, func(t *testing.T) {
			input := filepath.Join("testdata/pe-versions", c.Input)
			info, err := Inspect(input)
			check := func(err error, code string) {
				t.Helper()
				var coreErr *Error
				if !errors.As(err, &coreErr) || coreErr.Code != code {
					t.Fatalf("want %s, got %v", code, err)
				}
			}
			if c.DetectError != nil {
				check(err, *c.DetectError)
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if (info != nil) != c.Detected {
					t.Fatalf("detection: %v", info)
				}
				if info != nil && (info.Name != c.Family || info.Version != c.Version) {
					t.Fatalf("version: %+v", info)
				}
			}
			result, err := UnpackAll(input)
			if c.RecoveryError != nil {
				check(err, *c.RecoveryError)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			golden := input
			if c.Output != "" {
				golden = filepath.Join("testdata/pe-versions", c.Output)
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(contents(t, result.ReaderAt), want) {
				t.Fatal("native SDK differs from golden")
			}
			if c.Detected {
				if len(result.History) != 1 || result.History[0].Version != c.Version || len(result.Warnings) != 1 {
					t.Fatalf("metadata: %+v", result)
				}
				_, err = UnpackWithOptions(context.Background(), input, Options{})
				check(err, "unsupported")
			} else if len(result.History) != 0 {
				t.Fatal("undetected input changed")
			}
		})
	}
}

func TestGoSDKRealPackerVersionErrors(t *testing.T) {
	registry(t, builtins)
	data, err := os.ReadFile("testdata/retdec/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Samples []struct {
			Input, Family string
			ID            int `json:"compatibility_id"`
		}
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Samples) != 16 {
		t.Fatal("real version samples missing")
	}
	for _, s := range manifest.Samples {
		t.Run(s.Input, func(t *testing.T) {
			path := filepath.Join("testdata/retdec", s.Input)
			up, version := DetectFormat(path)
			if up == nil || up.Name() != s.Family || version != s.ID {
				t.Fatal("real version not recognized")
			}
			_, err := UnpackAll(path)
			var coreErr *Error
			if !errors.As(err, &coreErr) || coreErr.Code != "unsupported" {
				t.Fatalf("unverified recovery accepted: %v", err)
			}
		})
	}
}
