#!/usr/bin/env python3
"""Real gzip/zlib/XZ/LZMA payload fixtures generated and round-tripped with Python codecs."""
import gzip
import hashlib
import json
import lzma
import pathlib
import zlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEST = ROOT / 'testdata/payloads'


def gz(data):
    return gzip.compress(data, mtime=0)


def unxz(data):
    output = bytearray()
    while data:
        reader = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        output.extend(reader.decompress(data))
        assert reader.eof
        data = reader.unused_data
        padding = len(data) - len(data.lstrip(b'\x00'))
        assert padding % 4 == 0
        data = data[padding:]
    return bytes(output)


def main():
    DEST.mkdir(parents=True, exist_ok=True)
    plain = b'Executable analysis fixture\x00\xff\n' * 64
    pe = (ROOT / 'testdata/upx/pe32.original').read_bytes()
    upx = (ROOT / 'testdata/upx/pe32.packed').read_bytes()
    ap32 = (ROOT / 'testdata/aplib/tokens.ap32').read_bytes()
    xz = lambda data: lzma.compress(data, format=lzma.FORMAT_XZ)
    alone = lambda data: lzma.compress(data, format=lzma.FORMAT_ALONE)
    samples = [
        ('text-gzip', 'GZIP', gz(plain), plain, ['GZIP'], False),
        ('text-zlib', 'ZLIB', zlib.compress(plain), plain, ['ZLIB'], False),
        ('text-xz', 'XZ', xz(plain), plain, ['XZ'], False),
        ('text-lzma', 'LZMA', alone(plain), plain, ['LZMA'], True),
        ('pe32-gzip', 'GZIP', gz(pe), pe, ['GZIP'], False),
        ('pe32-zlib', 'ZLIB', zlib.compress(pe), pe, ['ZLIB'], False),
        ('pe32-xz', 'XZ', xz(pe), pe, ['XZ'], False),
        ('pe32-lzma', 'LZMA', alone(pe), pe, ['LZMA'], True),
        ('gzip-xz-upx', 'GZIP', gz(xz(upx)), (ROOT / 'testdata/upx/pe32.unpacked').read_bytes(), ['GZIP','XZ','UPX'], False),
        ('gzip-zlib-ap32', 'GZIP', gz(zlib.compress(ap32)), (ROOT / 'testdata/aplib/tokens.unpacked').read_bytes(), ['GZIP','ZLIB','AP32'], False),
        ('gzip-members', 'GZIP', gz(b'hello ') + gz(b'world'), b'hello world', ['GZIP'], False),
        ('xz-streams', 'XZ', xz(b'hello ') + b'\x00'*4 + xz(b'world'), b'hello world', ['XZ'], False),
        ('empty-gzip', 'GZIP', gz(b''), b'', ['GZIP'], False),
        ('empty-zlib', 'ZLIB', zlib.compress(b''), b'', ['ZLIB'], False),
        ('empty-xz', 'XZ', xz(b''), b'', ['XZ'], False),
        ('empty-lzma', 'LZMA', alone(b''), b'', ['LZMA'], True),
        ('pe32-xz-x86', 'XZ', lzma.compress(pe, filters=[{'id': lzma.FILTER_X86}, {'id': lzma.FILTER_LZMA2, 'preset': 6}]), pe, ['XZ'], False),
        ('delta-xz', 'XZ', lzma.compress(plain, filters=[{'id': lzma.FILTER_DELTA, 'dist': 3}, {'id': lzma.FILTER_LZMA2, 'preset': 6}]), plain, ['XZ'], False),
        ('sha256-xz', 'XZ', lzma.compress(plain, check=lzma.CHECK_SHA256), plain, ['XZ'], False),
    ]
    known = bytearray(alone(plain));known[5:13] = len(plain).to_bytes(8, 'little')
    samples.append(('known-size-lzma', 'LZMA', bytes(known), plain, ['LZMA'], True))
    manifest = {'generator': 'scripts/generate_payload_fixtures.py', 'zlib': zlib.ZLIB_RUNTIME_VERSION, 'samples': []}
    decoders = {'GZIP': gzip.decompress, 'ZLIB': zlib.decompress, 'XZ': unxz, 'LZMA': lambda b: lzma.decompress(b, format=lzma.FORMAT_ALONE)}
    for name, codec, packed, expected, history, explicit in samples:
        first = decoders[codec](packed)
        if len(history) == 1:
            assert first == expected, name
        (DEST / (name + '.packed')).write_bytes(packed)
        (DEST / (name + '.unpacked')).write_bytes(expected)
        manifest['samples'].append({'name': name, 'format': codec, 'packed': name + '.packed', 'unpacked': name + '.unpacked', 'history': history, 'explicit': explicit, 'packed_sha256': hashlib.sha256(packed).hexdigest(), 'unpacked_sha256': hashlib.sha256(expected).hexdigest()})
    (DEST / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    main()
