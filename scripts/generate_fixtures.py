#!/usr/bin/env python3
"""Generate benign real executable fixtures with LLVM and official UPX; never execute them."""
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEST = ROOT / "testdata" / "upx"


def run(*args):
    subprocess.run([str(a) for a in args], check=True)


def main():
    DEST.mkdir(parents=True, exist_ok=True)
    manifest = {"generator": "scripts/generate_fixtures.py", "upx": subprocess.check_output(["upx", "--version"], text=True).splitlines()[0], "samples": []}
    with tempfile.TemporaryDirectory() as temporary:
        tmp = pathlib.Path(temporary)
        cases = [("pe32", "i686-pc-windows-msvc", "x86"), ("pe64", "x86_64-pc-windows-msvc", "x64"), ("elf64", "x86_64-linux-gnu", None),
                 ("elf32", "i686-linux-gnu", None), ("elf-arm64", "aarch64-linux-gnu", None), ("macho64", "x86_64-apple-macos10.15", "macho")]
        for name, target, machine in cases:
            obj = tmp / (name + ".o")
            original = DEST / (name + ".original")
            packed = DEST / (name + ".packed")
            run("clang", "--target=" + target, "-O1", "-ffreestanding", "-fno-stack-protector", "-c", ROOT / "testdata/src/tiny.c", "-o", obj)
            if machine == "macho":
                run("ld64.lld", "-arch", "x86_64", "-platform_version", "macos", "10.15", "10.15", "-e", "_entry", "-no_pie", "-no_uuid", "-o", original, obj)
            elif machine:
                run("lld-link", "/entry:entry", "/subsystem:console", "/nodefaultlib", "/fixed", "/dynamicbase:no", "/timestamp:0", "/machine:" + machine, "/out:" + str(original), obj)
            else:
                run("ld.lld", "-e", "entry", "--build-id=none", "-o", original, obj)
            variants = [(name, ["--best"])]
            if machine == "macho":
                variants = [(name, ["--best", "--force-macos"])]
            if name == "pe32":
                variants += [("pe32-lzma", ["--lzma"]), ("pe32-filter", ["--filter=0x16"])]
            for variant, flags in variants:
                packed = DEST / (variant + ".packed")
                if packed.exists():
                    packed.unlink()
                run("upx", *flags, "--no-color", "-o", packed, original)
                info = subprocess.check_output(["upx", "--fileinfo", packed], text=True)
                method, filter_id = re.search(r"method (\d+),.*filter (0x[0-9a-fA-F]+)", info).groups()
                if variant == "pe32-lzma":
                    assert int(method) == 14, "UPX did not select LZMA"
                if variant == "pe32-filter":
                    assert int(filter_id, 16) == 0x16, "UPX silently disabled the requested filter"
                decoded = tmp / (variant + ".decoded")
                run("upx", "-d", "-q", "-o", decoded, packed)
                # UPX may normalize PE headers. The golden output is the official decoder's output.
                expected = DEST / (variant + ".unpacked")
                shutil.copyfile(decoded, expected)
                manifest["samples"].append({"name": variant, "flags": flags, "method": int(method), "filter": filter_id, "packed": packed.name, "original": original.name, "unpacked": expected.name,
                    "packed_sha256": hashlib.sha256(packed.read_bytes()).hexdigest(),
                    "unpacked_sha256": hashlib.sha256(expected.read_bytes()).hexdigest()})
    (DEST / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
