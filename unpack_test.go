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

func TestGoSDKAllFormatsAndRecovery(t *testing.T) {
	registry(t, builtins)
	for _, test := range []struct {
		name, section, marker string
		recover               bool
	}{
		{"ASPack", ".aspack", "", true}, {"FSG", ".packed", "FSG!", true}, {"WinUpack", ".upx0", "", true},
		{"Petite", ".petite", "", true}, {"PESpin", ".pespin", "", true}, {"Armadillo", ".EPACK", "", true},
		{"Themida", ".themida", "", true}, {"PECompact", ".pec", "", true}, {"NSPack", ".nsp0", "", true}, {"MPRESS", ".MPRESS1", "", true},
		{"VMProtect", ".vmp0", "", false}, {"Enigma", ".enigma1", "", false}, {"MEW", "MEW", "", false}, {"PELock", ".pelock", "", false}, {"PEBundle", ".pebundl", "", false}, {"Yoda", ".yP", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			data, err := testfixture.PE(test.section, test.marker)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "synthetic.exe")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			up, _ := DetectFormat(path)
			if up == nil || up.Name() != test.name {
				t.Fatal("incorrect detector")
			}
			_, err = UnpackWithOptions(context.Background(), path, Options{MaxDepth: 10})
			var coreErr *Error
			if !errors.As(err, &coreErr) || coreErr.Code != "unsupported" {
				t.Fatalf("strict mode: %v", err)
			}
			result, err := UnpackAll(path)
			if test.recover {
				if err != nil || len(result.Warnings) != 1 || result.History[0].Support != "recovery" {
					t.Fatalf("recovery: %v %v", result, err)
				}
			} else if err == nil {
				t.Fatal("detect-only format reported unpack success")
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

func TestGoSDKMissingEngineAndIOErrors(t *testing.T) {
	registry(t, builtins)
	if _, err := UnpackAll("missing.exe"); err == nil {
		t.Fatal("missing input accepted")
	}
	t.Setenv("UNPACK_RUST_BIN", filepath.Join(t.TempDir(), "missing-engine"))
	if _, err := Inspect(sample("pe32.packed")); err == nil {
		t.Fatal("missing engine accepted")
	}
	if up, version := DetectFormat(sample("pe32.packed")); up != nil || version != 0 {
		t.Fatal("legacy detection should return no match on failure")
	}
	if _, err := UnpackAll(sample("pe32.packed")); err == nil {
		t.Fatal("unpack hid missing engine")
	}
}

type envelope struct{ stall bool }

func (e envelope) Name() string { return "Envelope" }
func (e envelope) Detect(path string) int {
	b, _ := os.ReadFile(path)
	if bytes.HasPrefix(b, []byte("WRAP")) {
		return 1
	}
	return 0
}
func (e envelope) Unpack(path string) (io.ReaderAt, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !e.stall {
		b = b[4:]
	}
	return bytes.NewReader(b), nil
}

func TestGoCustomPluginsAndMixedLayers(t *testing.T) {
	registry(t, []string{"UPX"})
	RegisterFormat("Envelope", envelope{})
	packed, _ := os.ReadFile(sample("pe32.packed"))
	path := filepath.Join(t.TempDir(), "nested.exe")
	if err := os.WriteFile(path, append([]byte("WRAPWRAP"), packed...), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := UnpackAll(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.History) != 3 || result.History[2].PackerName != "UPX" {
		t.Fatalf("history: %+v", result.History)
	}
	golden, _ := os.ReadFile(sample("pe32.unpacked"))
	if !bytes.Equal(contents(t, result.ReaderAt), golden) {
		t.Fatal("mixed layer output")
	}
	result, err = Unpack(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.History) != 1 || !bytes.HasPrefix(contents(t, result.ReaderAt), []byte("WRAP")) {
		t.Fatal("depth ignored")
	}
	RegisterFormat("Envelope", envelope{stall: true})
	if _, err := Unpack(path, 0); err == nil {
		t.Fatal("unchanged output allowed infinite recursion")
	}
}

func TestGoCustomPluginsWithoutEngine(t *testing.T) {
	registry(t, nil)
	RegisterFormat("Envelope", envelope{})
	t.Setenv("UNPACK_RUST_BIN", filepath.Join(t.TempDir(), "no-engine"))
	path := filepath.Join(t.TempDir(), "wrapped")
	os.WriteFile(path, []byte("WRAPpayload"), 0600)
	result, err := Unpack(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents(t, result.ReaderAt)) != "payload" {
		t.Fatal("custom-only API regressed")
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

type recordedEnvelope struct {
	envelope
	paths *[]string
}

func (e recordedEnvelope) Unpack(path string) (io.ReaderAt, error) {
	*e.paths = append(*e.paths, path)
	return e.envelope.Unpack(path)
}

func TestCustomScratchReuseAndEngineErrors(t *testing.T) {
	registry(t, nil)
	paths := []string{}
	RegisterFormat("Envelope", recordedEnvelope{paths: &paths})
	path := filepath.Join(t.TempDir(), "wrapped")
	os.WriteFile(path, []byte("WRAPWRAPWRAPpayload"), 0600)
	result, err := Unpack(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents(t, result.ReaderAt)) != "payload" || len(paths) != 3 || paths[1] != paths[2] {
		t.Fatalf("scratch file not reused: %v", paths)
	}
	if _, err := os.Stat(paths[1]); !os.IsNotExist(err) {
		t.Fatal("scratch directory leaked")
	}
	RegisterFormat("UPX", RustUnpacker{Format: "UPX"})
	t.Setenv("UNPACK_RUST_BIN", filepath.Join(t.TempDir(), "missing-engine"))
	if _, err := UnpackAll(sample("pe32.packed")); err == nil {
		t.Fatal("custom registry hid Rust engine error")
	}
}

func TestCustomPathEnforcesNativePayloadLimit(t *testing.T) {
	registry(t, []string{"GZIP"})
	RegisterFormat("Envelope", envelope{})
	input, err := os.ReadFile(filepath.Join(testfixture.Root(), "testdata/payloads/pe32-gzip.packed"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "wrapped")
	os.WriteFile(path, append([]byte("WRAP"), input...), 0600)
	_, err = UnpackWithOptions(context.Background(), path, Options{MaxDepth: 10, MaxSize: 1024})
	var coreErr *Error
	if !errors.As(err, &coreErr) || coreErr.Code != "limit" {
		t.Fatalf("native output limit bypassed: %v", err)
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
