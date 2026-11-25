#!/usr/bin/env python3
"""Small synthetic PE layout fixtures; never claimed to be genuine ASPack-compressed programs."""
import copy
import hashlib
import json
import pathlib
import struct

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEST = ROOT / 'testdata/pe-versions'
# Independent fixture specifications. Tests must not derive their oracle from the Rust layout table.
LAYOUTS = [('2.1', 1, 0x4fd, 0x4f4, None), ('2.12', 2, 0x3b9, 0x748, 0x57c),
           ('other-0x41f', 3, 0x41f, 0x7a4, 0x5d8), ('2.42', 4, 0x42b, 0x7b0, 0x5e4)]


def put16(data, offset, value):
    struct.pack_into('<H', data, offset, value)


def put32(data, offset, value):
    struct.pack_into('<I', data, offset, value)


def pe(section='.aspack', prefix=0, reordered=False, is64=False, import_mode='repair', code_size=512, stub_size=4096):
    optional, header_size = 0x98, 512
    optional_size = 240 if is64 else 224
    table = optional + optional_size
    order = ['stub', 'code', 'imports'] if reordered else ['code', 'imports', 'stub']
    specs = {'code': ['.text', 0x1000, code_size, 0xc0000040], 'imports': ['.idata', 0x3000, 512, 0xc0000040], 'stub': [section, 0x7000, stub_size, 0xe0000060]}
    size = header_size + sum(s[2] for s in specs.values())
    data = bytearray(size)
    data[:2] = b'MZ';put32(data, 0x3c, 0x80);data[0x80:0x84] = b'PE\0\0'
    put16(data, 0x84, 0x8664 if is64 else 0x14c);put16(data, 0x86, 3)
    put16(data, 0x94, optional_size);put16(data, 0x96, 0x22 if is64 else 0x102)
    put16(data, optional, 0x20b if is64 else 0x10b);put32(data, optional+16, 0x7000+prefix)
    if is64:struct.pack_into('<Q', data, optional+24, 0x140000000)
    else:put32(data, optional+28, 0x400000)
    put32(data, optional+32, 4096);put32(data, optional+36, 512);put32(data, optional+56, 0xa000)
    put32(data, optional+60, header_size);put32(data, optional+64, 0x12345678);put16(data, optional+68, 3)
    directory = optional + (112 if is64 else 96)
    put32(data, directory-4, 0 if import_mode == 'none' else 16)
    offsets, headers = {}, {}
    cursor = header_size
    for i, key in enumerate(order):
        name, rva, raw_size, flags = specs[key]
        h = table+i*40;headers[key] = h;offsets[key] = cursor
        data[h:h+8] = name.encode().ljust(8, b'\0')
        put32(data, h+8, raw_size+4096);put32(data, h+12, rva);put32(data, h+16, raw_size)
        put32(data, h+20, cursor);put32(data, h+36, flags)
        cursor += raw_size
    data[offsets['code']:offsets['code']+32] = bytes(range(32))
    data[offsets['code']+16:offsets['code']+22] = b'\xb8\0\0\0\0\xc3'
    stub = offsets['stub']+prefix
    data[stub] = 0xe9;put32(data, stub+1, (0x1010-(0x7000+prefix)-5)&0xffffffff)
    if import_mode != 'none':
        p = offsets['imports'];put32(data, p, 0x3080);put32(data, p+12, 0x3040);put32(data, p+16, 0x30a0)
        data[p+64:p+77] = b'KERNEL32.dll\0'
        if is64:
            struct.pack_into('<Q', data, p+128, 0x30c0);struct.pack_into('<Q', data, p+160, 0x30c0)
        else:put32(data, p+128, 0x30c0);put32(data, p+160, 0x30c0)
        data[p+194:p+206] = b'ExitProcess\0'
        if import_mode == 'preserve':put32(data, directory+8, 0x3000);put32(data, directory+12, 40)
    return data, {'optional': optional, 'directory': directory, 'offsets': offsets, 'headers': headers, 'stub': stub, 'prefix': prefix, 'import_mode': import_mode, 'code_size': code_size, 'stub_size': stub_size}


def aspack(layout, **kwargs):
    data, meta = pe(**kwargs)
    name, version, signature, oep, blocks = layout
    data[meta['stub']+signature:meta['stub']+signature+6] = b'\x68\0\0\0\0\xc3'
    put32(data, meta['stub']+oep, 0x1010)
    if blocks is not None:put32(data, meta['stub']+blocks, 0)
    return data, meta


def recovered(data, meta, patches=()):
    expected = bytearray(data)
    put32(expected, meta['optional']+16, 0x1010);put32(expected, meta['optional']+64, 0)
    for key, h in meta['headers'].items():
        flags = struct.unpack_from('<I', expected, h+36)[0]
        put32(expected, h+36, flags | (0x60000020 if key == 'code' else 0x40000000))
    if meta['import_mode'] == 'repair':put32(expected, meta['directory']+8, 0x3000);put32(expected, meta['directory']+12, 40)
    for destination, plain in patches:expected[meta['offsets']['code']+destination:meta['offsets']['code']+destination+len(plain)] = plain
    return expected


def main():
    DEST.mkdir(parents=True, exist_ok=True)
    cases = []
    def add(name, family, version, data, meta, expected=None, error=None, detect_error=None, detected=True, profile=None, tags=()):
        item = {'name': name, 'family': family, 'version': version, 'profile': profile or family,
                'provenance': 'synthetic PE layout, not actual packer output', 'tags': list(tags),
                'input': name+'.bin', 'detected': detected, 'detect_error': detect_error,
                'recovery_error': error, 'expected_oep': 0x1010 if expected is not None else None,
                'pe64': struct.unpack_from('<H', data, meta['optional'])[0] == 0x20b,
                'entry_offset': meta['stub'], 'input_sha256': hashlib.sha256(data).hexdigest()}
        (DEST/item['input']).write_bytes(data)
        if expected is not None:
            item['output'] = name+'.recovered'
            item['output_sha256'] = hashlib.sha256(expected).hexdigest()
            (DEST/item['output']).write_bytes(expected)
        cases.append(item)
    for layout in LAYOUTS:
        profile, version, sig, oep, table = layout
        for variant, kwargs in [('basic', {}), ('shifted-entry', {'prefix': 17}), ('reordered-sections', {'prefix': 31, 'reordered': True}),
                                ('preserve-imports', {'import_mode': 'preserve'}), ('no-imports', {'import_mode': 'none'})]:
            data, meta = aspack(layout, **kwargs)
            add('aspack-'+profile+'-'+variant, 'ASPack', version, data, meta, recovered(data, meta), profile=profile, tags=[variant])
        for variant, value in [('zero-oep', 0), ('header-oep', 0x100), ('unbacked-oep', 0x1200), ('outside-oep', 0xffff0000)]:
            data, meta = aspack(layout);put32(data, meta['stub']+oep, value)
            add('aspack-'+profile+'-'+variant, 'ASPack', version, data, meta, error='unsupported', profile=profile, tags=[variant])
        data, meta = aspack(layout)
        other = next(x for x in LAYOUTS if x[1] != version)
        data[meta['stub']+other[2]:meta['stub']+other[2]+6] = b'\x68\0\0\0\0\xc3'
        add('aspack-'+profile+'-ambiguous', 'ASPack', 0, data, meta, error='invalid_input', detect_error='invalid_input', profile=profile, tags=['ambiguous-markers'])
        data, meta = aspack(layout)
        cut = sig+5;put32(data, meta['headers']['stub']+16, cut);data = data[:meta['offsets']['stub']+cut]
        add('aspack-'+profile+'-truncated-marker', 'ASPack', 0, data, meta, detected=False, profile=profile, tags=['truncated-marker'])
        if table is None:
            # The PUSH/RET bytes imply a very large DWORD at 0x500; this must never be read as a block count.
            data, meta = aspack(layout)
            assert struct.unpack_from('<I', data, meta['stub']+0x500)[0] > 1000
            add('aspack-'+profile+'-overlapping-ret', 'ASPack', version, data, meta, recovered(data, meta), profile=profile, tags=['ret-is-not-block-count'])
            continue
        for variant, relative, chunks in [('literal-block', False, [(b'\xe0ABC', b'ABC')]),
                                           ('relative-source', True, [(b'\xe0ABC', b'ABC')]),
                                           ('overlap-match', False, [(b'\x80A\xff\xff', b'AAA')]),
                                           ('two-blocks', False, [(b'\xe0ABC', b'ABC'), (b'\x80A\xff\xff', b'AAA')])]:
            data, meta = aspack(layout, prefix=23, reordered=True);put32(data, meta['stub']+table, len(chunks))
            patches=[]
            for i, (packed, plain) in enumerate(chunks):
                source=0x40+i*16;destination=0x40+i*32
                data[meta['offsets']['stub']+source:meta['offsets']['stub']+source+len(packed)] = packed
                struct.pack_into('<4I', data, meta['stub']+table+4+i*16, 0x1000+destination, len(packed), len(plain), source if relative else 0x7000+source)
                patches.append((destination, plain))
            add('aspack-'+profile+'-'+variant, 'ASPack', version, data, meta, recovered(data, meta, patches), profile=profile, tags=[variant, 'legacy-test-codec'])
        for variant, values, error in [
            ('source-outside', (0x1040,4,3,0xffffffff), 'invalid_input'),
            ('destination-headers', (0x100,4,3,0x7040), 'invalid_input'),
            ('destination-crosses-section', (0x11ff,4,3,0x7040), 'invalid_input'),
            ('oversized-output', (0x1040,4,0xffffffff,0x7040), 'limit'),
            ('short-stream', (0x1040,2,3,0x7040), 'invalid_input')]:
            data, meta = aspack(layout);data[meta['offsets']['stub']+0x40:meta['offsets']['stub']+0x44]=b'\xe0ABC'
            put32(data, meta['stub']+table, 1);struct.pack_into('<4I',data,meta['stub']+table+4,*values)
            add('aspack-'+profile+'-'+variant,'ASPack',version,data,meta,error=error,profile=profile,tags=[variant])
        for variant, count, error in [('unsupported-count',1001,'unsupported'),('truncated-table',200,'invalid_input')]:
            data, meta = aspack(layout);put32(data,meta['stub']+table,count)
            add('aspack-'+profile+'-'+variant,'ASPack',version,data,meta,error=error,profile=profile,tags=[variant])
        data, meta = aspack(layout);cut=oep+3;put32(data,meta['headers']['stub']+16,cut);data=data[:meta['offsets']['stub']+cut]
        add('aspack-'+profile+'-truncated-oep','ASPack',version,data,meta,error='unsupported',profile=profile,tags=['truncated-oep'])
    for family, section, marker, version in [('FSG','.packed','FSG!',1),('FSG','.packed','FSG2',2),('WinUpack','.packed','WinUpack',1),('WinUpack','.packed','UPack',2)]:
        for prefix in [0,29]:
            data,meta=pe(section=section,prefix=prefix)
            data[-len(marker):]=marker.encode()
            add(f'{family.lower()}-id{version}-entry{prefix}',family,version,data,meta,recovered(data,meta),tags=['signature-layout-id','relative-jump'])
    for is64 in [False,True]:
        for section in ['.MPRESS1','.MPRESS2']:
            data,meta=pe(section=section,is64=is64,prefix=19)
            add(f'mpress-{64 if is64 else 32}-{section[1:].lower()}','MPRESS',1,data,meta,recovered(data,meta),tags=['section-suffix-is-not-version','pe64' if is64 else 'pe32'])
    for family,section,support in [('Petite','.petite','recovery'),('PESpin','.pespin','recovery'),('Armadillo','.EPACK','recovery'),('Themida','.themida','recovery'),('PECompact','.pec','recovery'),('NSPack','.nsp0','recovery'),('VMProtect','.vmp0','detect_only'),('Enigma','.enigma1','detect_only'),('MEW','MEW','detect_only'),('PELock','.pelock','detect_only'),('PEBundle','.pebundl','detect_only'),('Yoda','.yP','detect_only')]:
        data,meta=pe(section=section,prefix=13)
        add(family.lower()+'-basic',family,1,data,meta,recovered(data,meta) if support=='recovery' else None,error='unsupported' if support=='detect_only' else None,tags=[support])
    manifest={'generator':'scripts/generate_version_fixtures.py','notice':'All generated cases are synthetic layout/boundary fixtures. Version IDs are compatibility/layout IDs, not proof of actual vendor packer output.','layouts':[{'label':x[0],'id':x[1],'signature_offset':x[2],'oep_offset':x[3],'block_table_offset':x[4]} for x in LAYOUTS],'cases':cases}
    (DEST/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(f'Generated {len(cases)} synthetic version/layout cases')


if __name__=='__main__':
    main()
