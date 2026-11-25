# UPX Go driver

This package preserves `UPX`, `UPX_VER_*`, `UPXHeader`, `Name`, `Detect` and `Unpack`.
Its implementation now delegates to the Rust core, which uses official UPX for
actual decompression rather than the old approximate NRV/filter implementation.

See the [main README](../README.md) for engine installation, runtime requirements
and the Go SDK. Real PE32, PE64, ELF64, LZMA and filter fixtures are in
[../testdata/upx](../testdata/upx); their provenance is documented in
[../testdata/README.md](../testdata/README.md).
