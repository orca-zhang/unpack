# Fixture provenance

`src/tiny.c` is a benign executable fixture source under this repository's MIT
license. It contains a small function call and a 64 KiB data section. It does not
open files, access the network or spawn processes. Tests inspect/decompress the
binaries and never execute them.

`upx/` contains checked-in PE32/64, ELF32/x86-64/ARM64 and x86-64 Mach-O originals, real official-UPX packed
files, and official-decoder golden outputs. PE32 also has explicit LZMA and x86
filter `0x16` variants. `manifest.json` records UPX version, compression flags, the
actual method/filter reported by UPX, and
SHA-256 hashes. UPX may normalize a PE header, so golden output comes from the
official decoder rather than assuming whole-file equality with the original.

Regenerate with Python 3, LLVM `clang`, `lld-link`, `ld.lld`, `ld64.lld`, and UPX on PATH:

```sh
python3 scripts/generate_fixtures.py
```

Fixtures are checked in; Rust/Go tests need UPX but do not need LLVM or Python.
The separate CI chart check uses standard-library Python.
Toolchain or UPX version changes may change the generated binary bytes: review
and commit the regenerated manifest and fixtures together. Tests fail rather than
skip when a required fixture or backend is absent.

Synthetic fixtures in `tests/core.rs` rename
a section of the benign PE fixture and add a simple tail jump or ASPack marker.
They validate detection, recovery control flow, preservation of original code and
error handling. They are **not** genuine outputs of FSG, WinUpack, commercial VM
protectors or other packers, and do not establish full unpacking support.

`aspack/aspack_test.exe` predates the Rust migration. Its provenance was
not recorded by the original repository. It remains a regression sample for
recognition and limited PE repair only. Tests do not run it or claim its compressed
program is restored.

## Native aPLib / AP32 vectors

`aplib/` contains five AP32 containers, corresponding raw streams, SHA-256 manifests,
and decoded payloads. Regenerate with standard-library Python only:

```sh
python3 scripts/generate_aplib_fixtures.py
```

The test encoder emits explicit literal/match tokens, including short and long
copies, repeated offsets, zero literals, overlapping copies and distance thresholds
127/128, 1279/1280, 31999/32000. It is not an optimizing compressor: literal-only
PE/UPX wrappers may be larger than their input and are excluded from compression
ratio charts. `nested.ap32` wraps another AP32 container. `upx.ap32` contains the
real UPX PE32 fixture; normal unpacking must record AP32 then UPX and match the
official UPX decoder's golden result. These are container chains, not commercial
protector stubs.

Both raw streams and containers were verified against the independent `aplib 0.8`
decoder from PyPI with strict checking. Verifier wheel SHA-256:
`a015bb3ed6bf95d9d20a7b93f4f55bbdfdeb8cf8ab5fdee05152f114aa49dfd4`.
That verifier is not bundled, linked, imported by this project or required for
tests; no verifier source was copied into the Rust implementation.

## Native compression payloads

`payloads/` has 20 cases produced and round-tripped with independent Python
`gzip`, `zlib` and `lzma` implementations, with packed/output SHA-256 manifests.
They cover all four codecs, empty streams, GZIP members, padded concatenated XZ
streams, XZ BCJ/delta/SHA-256, known-size LZMA and two three-layer chains:
GZIP -> XZ -> UPX and GZIP -> ZLIB -> AP32.

```sh
python3 scripts/generate_payload_fixtures.py
```

LZMA-Alone is tested by explicit format selection; it is never automatically
guessed. XZ/LZMA decoding has a 64 MiB dictionary/model budget. Raw payload
support is separate from full unpacking of PE protectors using these algorithms.

The eight UPX variants include experimental x86-64 Mach-O produced using
`--force-macos`. Tests compare the official decoder's bytes and validate structure;
they do not establish macOS execution compatibility. ARM64 Mach-O was excluded
after upstream UPX rejected decoding the generated candidate. Mach-O universal
and byte-order tests are structural fixtures, not real packed universal programs.

## PE version and boundary matrix

`pe-versions/` contains **105 synthetic inputs**, generated with independent explicit
layout specifications by `scripts/generate_version_fixtures.py`. **81 cases** cover
ASPack 2.1, 2.12, OTHER (`0x41f`) and 2.42. The remaining cases cover FSG and
WinUpack signature IDs, MPRESS PE32/64 section variants, and other PE families.
They vary entry-point offsets, section order, import tables, OEP validity,
truncation, ambiguous markers, block sources/destinations and overlapping matches.
Positive cases have byte-for-byte expected repair outputs and SHA-256 manifests.
Rust verifies PE structure; Go checks SDK values/errors and the same golden bytes.

```sh
python3 scripts/generate_version_fixtures.py
```

These fixtures are **not vendor packer output**. The limited legacy block test
codec is not a complete ASPack decompressor. ASPack 2.1 has no supported block table:
the old guessed offset overlaps the stub's RET byte. ASPack 2.42/OTHER currently
have synthetic layout coverage only, not verified commercial unpacking.

## Real legacy packer versions

`retdec/` imports 16 regression inputs and one unpacked reference from
[Avast RetDec regression tests](https://github.com/avast/retdec-regression-tests),
commit `8d8087f906c3d38c0cce8fcfb15acf3228c5e532`. The upstream MIT notice is preserved
in `retdec/LICENSE`. `retdec/manifest.json` records each source path, URL and SHA-256.
Vendor versions come from upstream test names/expectations, not section suffixes.

- ASPack 2.12: C sample; recognition and rejection of unverified recovery.
- FSG 1.33: recursive factorial sample; recognition and rejection of unverified recovery.
- MPRESS 1.05, 1.27, 2.05, 2.19: Hello World samples with code before/after/between data.
- MPRESS 2.19 MSVC: LZMA and LZMAT variants.

The upstream `mpress_105_code_after_data-unpacked` reference has entry point
`0x3000`. A stub jump into the compressed `.MPRESS1` section targets `0x102f`,
which proves that selecting a plausible branch is insufficient. Recovery must
reject destinations in the stub or known packed storage. Tests require every
imported packed sample to return `unsupported` in recovery mode; they do not
claim native MPRESS/FSG/ASPack decompression. The legacy repository ASPack 2.1
sample remains covered separately as limited PE repair. No imported executable
is run during tests.
