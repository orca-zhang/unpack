# Technical reference

[English](REFERENCE.md) · [中文](REFERENCE_zh.md) · [README](../README.md)

<a id="versions"></a>

## Version and layout details

### ASPack layout versions

Offsets are relative to the PE entry-point stub. These labels describe recognized
layouts; they do not certify complete unpacking of every executable from that release.

| Layout label | Compatibility ID | Marker offset | Original-entry-point field | Legacy block table | Capability |
| --- | ---: | --- | --- | --- | --- |
| 2.1 | 1 | `0x4fd` | `0x4f4` | None | Entry-point / PE repair; overlapping RET bytes are not a block count |
| 2.12 | 2 | `0x3b9` | `0x748` | `0x57c` | PE repair + limited legacy block layout |
| OTHER (`0x41f`) | 3 | `0x41f` | `0x7a4` | `0x5d8` | PE repair + limited legacy block layout; vendor version unknown |
| 2.42 | 4 | `0x42b` | `0x7b0` | `0x5e4` | PE repair + limited legacy block layout |

Source: [Rust layout definitions](../rust/aspack.rs), [recovery implementation](../rust/recover.rs)
and [synthetic layout manifest](../testdata/pe-versions/manifest.json).
The legacy block decoder is not a complete native ASPack codec.

### UPX versions, architectures and methods

The checked-in fixtures use **official UPX 5.1.0**. Other UPX releases depend on the
installed backend and input; this repository does not establish a 1.x–5.x compatibility range.

| Fixture | Executable variant | Packing selection | Actual method / filter | Validation |
| --- | --- | --- | --- | --- |
| `pe32` | PE32 / x86 | `--best` | `2` / `0x16` | Official-decoder bytes + SHA-256 |
| `pe32-lzma` | PE32 / x86 | `--lzma` | `14` / `0x16` | Official-decoder bytes + SHA-256 |
| `pe32-filter` | PE32 / x86 | `--filter=0x16` | `2` / `0x16` | Official-decoder bytes + SHA-256 |
| `pe64` | PE32+ / x86-64 | `--best` | `2` / `0x00` | Official-decoder bytes + SHA-256 |
| `elf32` | ELF32 / x86 | `--best` | `2` / `0x00` | Official-decoder bytes + SHA-256 |
| `elf64` | ELF64 / x86-64 | `--best` | `2` / `0x00` | Official-decoder bytes + SHA-256 |
| `elf-arm64` | ELF64 / ARM64 | `--best` | `2` / `0x00` | Official-decoder bytes + SHA-256 |
| `macho64` | Thin Mach-O 64 / x86-64 | `--best --force-macos` | `2` / `0x49` | Official-decoder bytes + structure; experimental packing |

Source: [UPX fixture manifest](../testdata/upx/manifest.json).
Mach-O execution compatibility is unverified; ARM64 Mach-O is not a verified round trip.

### Compatibility IDs are not vendor versions

The detector checks section evidence before string evidence. The mappings below
apply when the listed evidence wins; a different earlier match can take priority.

| Family | Evidence → current `version` ID | Meaning |
| --- | --- | --- |
| UPX | `UPX0` / `UPX1` / `UPX!` → 1 | Legacy Go constants 1–4 do not prove four supported UPX releases |
| FSG | `FSG!` → 1; `FSG2` → 2 | Signature variants, not a verified 1.x / 2.x release range |
| WinUpack | `.upx0` / `.upx1` → 1; `WinUpack` → 1; `UPack` → 2 | `WinUpack!` also matches the earlier `WinUpack` signature |
| PECompact | Section → 1; `PECompact` → 1; `PEC2` → 2; `PEC1` → 3 | Signature ordering, not vendor-version ordering |
| MPRESS | `.MPRESS1` / `.MPRESS2` → 1; `MPRESS` string → 1 | Section suffixes 1 / 2 do not distinguish product releases |

### Executable container variants

| Container | Structural handling | Real UPX round-trip fixtures |
| --- | --- | --- |
| PE | PE32 (`0x10b`), PE32+ (`0x20b`) | x86 / x86-64 |
| ELF | ELF32 / ELF64, little / big endian header validation | Little-endian x86 / x86-64 / ARM64 |
| Mach-O | Thin 32 / 64-bit, universal FAT32 / FAT64, both byte orders | Thin x86-64 only |

Structural validation covers more variants than the real packed fixture corpus.
It is not proof of unpacking every CPU, container version or commercial protector.

## Detection and recovery

Detection uses PE sections and packer-specific signatures in a stable order.
Generic instructions such as `PUSHAD; CALL` are not sufficient evidence. In
particular, `.vmp*` identifies VMProtect rather than Themida. Detection is still
heuristic: renamed sections, modified stubs and unrelated strings can affect it.
`version` is a compatibility ID matching the Go constants, not a vendor version.

Static recovery restores a plausible entry point and repairs selected PE fields.
It does **not** implement general decompression, devirtualization, anti-debugging
bypass, or guarantee a runnable file. The existing ASPack sample is covered by
structure/entry-point tests, not a successful execution test. Rust and the CLI
require explicit recovery opt-in; the old Go methods keep recovery enabled for
compatibility and return `Warnings` on the aggregate result.

## Build and install

Requires Rust 1.85+; Go 1.21.5+ is needed only for the Go SDK. Install official
[UPX](https://upx.github.io/) for UPX unpacking (5.1.0 was used for the fixtures).
Detection, AP32, all four payload codecs and static recovery require no external decompressor. No analyzed executable is run.

```sh
cargo build --release --locked
# Or install the Rust executable on PATH:
cargo install --path . --locked
```

The Go SDK needs `unpack-rs` at runtime. It searches `UNPACK_RUST_BIN`, then PATH,
then local `target/release` and `target/debug` directories. It never builds Rust or
downloads programs automatically. Set `UNPACK_UPX` to choose an official UPX
executable outside PATH. Both environment variables are executable paths, not
shell commands. No cgo, static-library linker setup or Go module dependencies are
required. When both local profiles exist, the newest binary is selected to avoid using a stale build.

<a id="cli"></a>

## Rust CLI

```sh
unpack-rs detect testdata/upx/pe32.packed
unpack-rs detect --json testdata/upx/elf64.packed
unpack-rs unpack -o output.exe testdata/upx/pe32.packed
unpack-rs unpack -o decoded.exe testdata/aplib/upx.ap32
unpack-rs unpack -o decoded.exe testdata/payloads/gzip-xz-upx.packed
unpack-rs unpack --format LZMA -o payload.bin testdata/payloads/text-lzma.packed
unpack-rs unpack --depth 5 --max-size 268435456 input.exe
unpack-rs unpack --recover -o recovered.exe aspack/testdata/aspack_test.exe
unpack-rs formats
```

The default output is `<stem>_unpacked.<extension>`. Existing files are preserved
unless `--force` is provided; the input itself cannot be overwritten. Output is
written to a temporary file in the destination directory before publication.
Default limits are 10 layers, 256 MiB per input/output and 30 seconds per UPX
process. `--depth 0` removes the configured depth limit, with an absolute cap of
1024 layers and cycle detection. Intermediate layers remain in memory; UPX alone
needs private temporary input/output files, removed on normal completion/error.
UPX's own process memory is not constrained by the output file limit.
XZ/LZMA have a separate fixed 64 MiB decoder dictionary/model memory budget.
LZMA-Alone has no reliable magic and is never guessed automatically. Explicit
format selection decodes one layer; recursive mode validates recognized inner
containers/executables. ZLIB preset-dictionary streams are reported as unsupported.
LZMA-Alone has no checksum; strict completion and declared output size are checked.

The x86-64 Mach-O fixture uses upstream UPX's experimental `--force-macos` packing
option. Tests verify decoded bytes/structure, not packed-program execution on macOS.
ARM64 Mach-O is not listed as a verified round-trip case.

## Go SDK

Existing imports and calls continue to compile. Deploy the matching Rust binary
alongside the application or install it on PATH.

```go
package main

import (
    "fmt"
    "github.com/orca-zhang/unpack"
    _ "github.com/orca-zhang/unpack/drivers"
)

func main() {
    result, err := unpack.UnpackAll("packed.exe")
    if err != nil { panic(err) }
    for _, layer := range result.History {
        fmt.Println(layer.PackerName, layer.Version, layer.Support)
    }
    for _, warning := range result.Warnings { fmt.Println(warning) }
    // result.ReaderAt owns an in-memory result; it needs no Close.
}
```

Import individual drivers (for example `_ "github.com/orca-zhang/unpack/upx"`) to
register only those formats. Import `drivers` to register all 22, or import
`github.com/orca-zhang/unpack/ap32` for native AP32 support. `Inspect(path)`
reports detection evidence and errors for all built-ins regardless of registration;
legacy `DetectFormat` keeps its no-match-on-error signature and uses registered
formats. Custom Go drivers retain priority in sorted registration-name order.

For explicit limits, cancellation and strict unpacking:

```go
result, err := unpack.UnpackWithOptions(ctx, path, unpack.Options{
    MaxDepth: 10,
    MaxSize: 256 * 1024 * 1024,
    AllowRecovery: false,
})
```

Rust errors are exposed as `*unpack.Error` with codes `invalid_input`, `unsupported`,
`limit`, `backend`, or `io`. Engine discovery/transport failures are ordinary Go
errors. A built-in recursive operation uses one Rust process with protocol 2:
a JSON metadata line followed by raw binary output. The Go result reuses the
received buffer, removing base64 encoding/decoding and its payload allocation.
Protocol 1 remains available for older clients; the current Go SDK requires a
matching protocol-2 Rust engine. Go adds a two-minute request timeout. Process
startup and pipe I/O still have a cost; this is not an in-process binding.
Custom plugins reuse a single private scratch file between layers. The mixed
custom/native path reuses detection metadata, propagates engine errors and applies
native size/context limits. Plugin code is responsible for its own runtime/resources.

For explicit one-layer LZMA decoding without registration:

```go
result, err := unpack.UnpackWithOptions(ctx, path, unpack.Options{Format: "LZMA"})
```

Named `gzip`, `zlib`, `xz` and `lzma` Go packages also expose the standard driver API.

## Rust library

```rust
use unpack::{Options, unpack_path};

fn main() -> unpack::Result<()> {
    let result = unpack_path("packed.exe", &Options::default())?;
    for layer in result.history { println!("{}", layer.packer_name); }
    Ok(())
}
```

`detect(&[u8])`, `detect_format`, `unpack(&[u8], &Options)`, `unpack_path` and
`unpack_format` accept data or paths without requiring the Go SDK. Named-format
unpacking performs exactly one layer, matching individual Go driver methods.
Recovery stops after one repair because packer section names may remain in the
result; that is not evidence of another layer.

`unpack_owned(Vec<u8>, &Options)` and `unpack_format_owned` consume an existing
buffer without the initial whole-file clone. The CLI and `unpack_path` use this
path. `aplib::decompress(raw, max_size)` decodes raw aPLib data; automatic detection
requires an AP32 header because a raw stream has no reliable magic. AP32 size and
packed/unpacked CRCs are checked; malformed offsets, missing end markers and
over-limit output are errors. AP32 support does not imply full support for PE
packers that happen to use aPLib internally.
`compression::unpack(data, format, max_size)` directly decodes one GZIP/ZLIB/XZ/LZMA
payload, including arbitrary data. Mach-O validation covers thin/universal 32/64-bit
structures in both byte orders; real UPX samples currently cover x86-64 thin Mach-O.

Runnable SDK examples:

```sh
cargo run --example basic -- testdata/upx/pe32.packed
go run ./examples/go testdata/upx/elf64.packed
```

## Tests and fixtures

```sh
cargo build --locked
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
go test -race ./...
go vet ./...
```

Eight real UPX variants cover PE32, PE64, ELF32/x86-64/ARM64, x86-64 Mach-O,
LZMA and an x86 filter. Twenty independent payload fixtures cover empty streams,
concatenation, XZ BCJ/delta/SHA-256, known-size LZMA and GZIP -> XZ -> UPX chains.
Tests check official-decoder output and SHA-256 manifests, not just file length or
a changed entry point. Five additional AP32/raw aPLib vectors cover token types,
offset boundaries, nested containers and a real AP32 -> UPX chain. They were
checked using an independent decoder; see the fixture provenance. Synthetic PE
fixtures cover all 17 PE packer detectors, legacy static
recovery, unsupported formats, malformed headers, limits, SDK registration,
custom Go plugins and mixed layers. Synthetic stubs are not evidence that a real
commercial protector can be unpacked. These tests do not skip missing fixtures.
See [testdata/README.md](../testdata/README.md) for provenance and regeneration.

CI runs Rust and Go checks on Linux, macOS and Windows. Building the Go SDK with
`CGO_ENABLED=0` remains supported. This is a version-2 runtime migration: `go get`
alone no longer installs everything needed for built-in unpacking.

## Rebuild the charts

All seven charts have English and Chinese versions, share a vector style and are generated from checked-in measurements,
fixture sizes and live format metadata. [The report](REPORT.md) includes the
detailed detection, CRC/AP32, SDK allocation and fixture-size charts.

```sh
make benchmark  # Re-measure the current implementation; preserves historical baseline
make charts     # Regenerate SVGs from measurements and live format metadata
python3 scripts/generate_charts.py --check
```

CI checks chart freshness without rerunning machine-dependent benchmarks.
The [logo](assets/logo.svg) and [header artwork](assets/hero.svg) are standalone,
editable SVGs; chart generation uses only the Python standard library.
