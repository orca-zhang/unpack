#!/usr/bin/env python3
"""Build independently verifiable aPLib token streams; this is a test encoder, not a compressor."""
import hashlib
import json
import pathlib
import struct
import zlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEST = ROOT / 'testdata/aplib'


class Stream:
    def __init__(self, first):
        self.data = bytearray([first])
        self.plain = bytearray([first])
        self.left = 0
        self.tag = 0
        self.was_match = False
        self.last_offset = 0

    def bit(self, value):
        if not self.left:
            self.tag = len(self.data)
            self.data.append(0)
            self.left = 8
        self.left -= 1
        self.data[self.tag] |= value << self.left

    def bits(self, values):
        for value in values:
            self.bit(int(value))

    def gamma(self, value):
        assert value >= 2
        digits = bin(value)[3:]
        for i, value in enumerate(digits):
            self.bit(int(value))
            self.bit(int(i + 1 != len(digits)))

    def literal(self, value):
        self.bit(0)
        self.data.append(value)
        self.plain.append(value)
        self.was_match = False

    def copy(self, offset, length):
        assert 0 < offset <= len(self.plain)
        for _ in range(length):
            self.plain.append(self.plain[-offset])

    def short(self, offset, length):
        assert 1 <= offset <= 127 and length in (2, 3)
        self.bits('110')
        self.data.append(offset * 2 + length - 2)
        self.copy(offset, length)
        self.was_match, self.last_offset = True, offset

    def nibble(self, offset):
        assert 0 <= offset < 16
        self.bits('111' + f'{offset:04b}')
        if offset:
            self.copy(offset, 1)
        else:
            self.plain.append(0)
        self.was_match = False

    def long(self, offset, length):
        adjustment = int(offset >= 32000) + int(offset >= 1280) + (2 if offset < 128 else 0)
        self.bits('10')
        self.gamma((offset >> 8) + (2 if self.was_match else 3))
        self.data.append(offset & 255)
        self.gamma(length - adjustment)
        self.copy(offset, length)
        self.was_match, self.last_offset = True, offset

    def reuse(self, length):
        assert not self.was_match and self.last_offset > 0
        self.bits('10')
        self.gamma(2)
        self.gamma(length)
        self.copy(self.last_offset, length)
        self.was_match = True

    def finish(self):
        self.bits('110')
        self.data.append(0)
        return bytes(self.data), bytes(self.plain)


def literals(data):
    assert data
    stream = Stream(data[0])
    for value in data[1:]:
        stream.literal(value)
    return stream.finish()


def container(packed, plain):
    return struct.pack('<4s5I', b'AP32', 24, len(packed), zlib.crc32(packed), len(plain), zlib.crc32(plain)) + packed


def main():
    DEST.mkdir(parents=True, exist_ok=True)
    stream = Stream(ord('A'))
    stream.literal(ord('B'))
    stream.short(2, 3)
    stream.nibble(1)
    stream.nibble(0)
    stream.literal(ord('C'))
    stream.reuse(3)
    stream.long(3, 5)
    stream.long(5, 4)
    vectors = [('tokens', *stream.finish())]
    stream = Stream(0)
    for i in range(1, 32000):
        stream.literal(i % 251)
    for offset in [127, 128, 1279, 1280, 31999, 32000]:
        adjustment = int(offset >= 32000) + int(offset >= 1280) + (2 if offset < 128 else 0)
        stream.long(offset, 2 + adjustment)
    vectors.append(('offsets', *stream.finish()))
    for name, file in [('pe32', 'pe32.original'), ('upx', 'pe32.packed')]:
        vectors.append((name, *literals((ROOT / 'testdata/upx' / file).read_bytes())))
    inner = container(vectors[0][1], vectors[0][2])
    vectors.append(('nested', *literals(inner)))
    manifest = {'generator': 'scripts/generate_aplib_fixtures.py', 'encoder': 'test token/literal encoder (not a compression ratio benchmark)', 'samples': []}
    for name, packed, plain in vectors:
        wrapped = container(packed, plain)
        for suffix, data in [('.aplib', packed), ('.ap32', wrapped), ('.unpacked', plain)]:
            (DEST / (name + suffix)).write_bytes(data)
        manifest['samples'].append({'name': name, 'packed': name + '.ap32', 'raw': name + '.aplib', 'unpacked': name + '.unpacked', 'packed_sha256': hashlib.sha256(wrapped).hexdigest(), 'unpacked_sha256': hashlib.sha256(plain).hexdigest()})
    (DEST / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    main()
