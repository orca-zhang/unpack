#!/usr/bin/env python3
"""Deterministic SVG charts from checked-in measurements and format/fixture metadata; stdlib only."""
import argparse
from collections import Counter, defaultdict
from html import escape
import json
import math
import pathlib
import re
import statistics
import subprocess
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCS = ROOT / 'docs'
COLORS = {'before': '#a9bab7', 'after': '#157d70', 'unpack': '#157d70', 'recovery': '#b87930', 'detect_only': '#657b89'}
SVG_NS = 'http://www.w3.org/2000/svg'
ET.register_namespace('', SVG_NS)


def log_width(value, maximum, width):
    """Compress large ratios while preserving order; labels retain the measured values."""
    return width * math.log1p(value) / math.log1p(maximum)


def chinese_svg(content, labels):
    root = ET.fromstring(content)
    root.set('lang', 'zh-CN')
    for element in root.iter():
        if 'font-family' in element.attrib:
            element.set('font-family', 'Arial, "PingFang SC", "Microsoft YaHei", "Noto Sans CJK SC", sans-serif')
        if element.tag.rsplit('}', 1)[-1] in ('text', 'title', 'desc') and element.text:
            value = labels['text'].get(element.text, element.text)
            for pattern, replacement in labels['patterns']:
                value = re.sub(pattern, replacement, value)
            element.text = value
    return ET.tostring(root, encoding='unicode') + '\n'


def text(x, y, value, size=14, color='#526966', anchor='start'):
    return f'<text x="{x}" y="{y}" font-size="{size}" fill="{color}" text-anchor="{anchor}">{escape(str(value))}</text>'


def box(x, y, width, height, fill, radius=5):
    return f'<rect x="{x}" y="{y}" width="{max(width, 0):.3f}" height="{height}" rx="{radius}" fill="{fill}"/>'


def svg(title, description, height, parts):
    result = f'<svg xmlns="http://www.w3.org/2000/svg" width="900" height="{height}" viewBox="0 0 900 {height}" role="img" aria-labelledby="title desc">\n<title id="title">{escape(title)}</title>\n<desc id="desc">{escape(description)}</desc>\n<g font-family="Arial, Helvetica, sans-serif">\n'
    result += box(0.5, 0.5, 899, height - 1, '#f5f9f7', 16)
    result += '<rect x="0.5" y="0.5" width="899" height="' + str(height - 1) + '" rx="16" fill="none" stroke="#dce6e1"/>'
    result += box(28, 22, 4, 22, COLORS['after'], 2) + text(44, 39, title, 22, '#152e2b') + text(28, 65, description, 12)
    result += '<path d="M28 80H872" stroke="#dce6e1"/>'
    result += '\n'.join(parts) + '</g></svg>\n'
    ET.fromstring(result)
    return result


def support_chart(formats):
    counts = Counter(f['support'] for f in formats)
    parts = []
    total = len(formats)
    x = 28
    for key, label in [('unpack', 'Full decode paths'), ('recovery', 'Static PE recovery'), ('detect_only', 'Detection only')]:
        width = 844 * counts[key] / total
        parts.append(box(x, 100, width, 38, COLORS[key], 0))
        parts.append(text(x + width / 2, 125, counts[key], 18, '#ffffff', 'middle'))
        x += width
    for i, (key, label) in enumerate([('unpack', 'Full decode paths'), ('recovery', 'Static PE recovery'), ('detect_only', 'Detection only')]):
        y = 178 + i * 63
        names = ', '.join(f['name'] for f in formats if f['support'] == key)
        parts += [box(28, y - 13, 14, 14, COLORS[key]), text(52, y, f'{label}: {counts[key]}', 16, '#0f172a'), text(52, y + 22, names, 12)]
    parts.append(text(28, 370, '5 native decoders + 1 external UPX path. LZMA requires explicit selection.', 12))
    return svg(f'Format support: {total} built-in formats', 'Capability categories, not a claim of full commercial protector removal.', 394, parts)


def fixture_chart():
    manifest = json.loads((ROOT / 'testdata/upx/manifest.json').read_text(encoding='utf-8'))
    rows = []
    for sample in manifest['samples']:
        directory = ROOT / 'testdata/upx'
        rows.append((sample['name'], (directory / sample['packed']).stat().st_size, (directory / sample['unpacked']).stat().st_size))
    maximum = max(u for _, _, u in rows)
    parts = [text(28, 92, 'Sample', 12), text(700, 92, 'Packed / unpacked bytes', 12), text(872, 92, 'Ratio', 12, anchor='end')]
    for i, (name, packed, unpacked) in enumerate(rows):
        y = 125 + i * 65
        parts += [text(28, y + 10, name), box(155, y - 8, 505 * unpacked / maximum, 19, '#d4e0db'), box(155, y + 14, 505 * packed / maximum, 12, COLORS['after']), text(700, y + 9, f'{packed:,} / {unpacked:,}', 12), text(872, y + 9, f'{packed / unpacked:.1%}', 13, anchor='end')]
    legend = 125 + len(rows) * 65 + 15
    parts += [box(155, legend, 14, 12, '#d4e0db'), text(176, legend + 11, 'Unpacked'), box(310, legend, 14, 12, COLORS['after']), text(332, legend + 11, 'Packed'), text(28, legend + 45, 'Benign tiny C fixtures; sizes are test data, not representative malware or compression benchmarks.', 12)]
    return svg('Real UPX fixture sizes', f'{len(rows)} checked-in variants; golden output is produced by the official decoder.', legend + 69, parts)


def codec_chart():
    before = {m['name']: m for m in json.loads((DOCS / 'benchmarks/codecs-before.json').read_text(encoding='utf-8'))}
    after = {m['name']: m for m in json.loads((DOCS / 'benchmarks/codecs-after.json').read_text(encoding='utf-8'))}
    parts = []
    for i, (key, label) in enumerate([('crc32_65kib', 'CRC32: 65 KiB input'), ('ap32_65kib', 'AP32: verify both CRCs and decode 65 KiB')]):
        y = 114 + i * 157
        old, new = before[key]['median_ns'], after[key]['median_ns']
        maximum = max(old, new)
        parts.append(text(28, y, label, 16, '#0f172a'))
        for j, (value, color, name) in enumerate([(old, COLORS['before'], 'Before'), (new, COLORS['after'], 'After')]):
            row = y + 20 + j * 36
            parts += [text(28, row + 16, name, 12), box(100, row, log_width(value / 1000, maximum / 1000, 565), 24, color), text(687, row + 17, f'{value / 1000:,.2f} us', 13)]
        parts.append(text(870, y, f'{old / new:.2f}x ratio', 19, '#152e2b', 'end'))
    parts += [text(28, 419, 'Five batches of 200 calls. Median batch-average latency; lower is better. Excludes I/O and startup.', 12), text(28, 440, 'Logarithmic bar lengths; labels show measured values. Each panel uses its own scale.', 12)]
    return svg('Native AP32: faster checksums and decoding', 'crc32fast replaces the byte-by-byte bit loop; CRC polynomial and results remain unchanged.', 465, parts)


def native_chart():
    before = {m['name']: m for m in json.loads((DOCS / 'benchmarks/baseline.json').read_text(encoding='utf-8'))}
    after = {m['name']: m for m in json.loads((DOCS / 'benchmarks/optimized.json').read_text(encoding='utf-8'))}
    parts = []
    for i, (key, label, unit) in enumerate([('detect_plain_pe', 'Plain PE: no packer match', 1000), ('detect_upx_pe', 'UPX PE: section match', 1)]):
        y = 114 + i * 157
        old, new = before[key]['median_ns'], after[key]['median_ns']
        maximum = max(old, new)
        suffix = 'us' if unit == 1000 else 'ns'
        parts += [text(28, y, label, 16, '#0f172a')]
        for j, (value, color, name) in enumerate([(old, COLORS['before'], 'Before'), (new, COLORS['after'], 'After')]):
            row = y + 20 + j * 36
            parts += [text(28, row + 16, name, 12), box(100, row, log_width(value / unit, maximum / unit, 565), 24, color), text(687, row + 17, f'{value / unit:,.2f} {suffix}', 13)]
        change = (new / old - 1) * 100
        label = f'{old / new:.2f}x faster' if new < old else f'+{change:.1f}% latency'
        parts.append(text(870, y, label, 19, '#152e2b', 'end'))
    parts += [text(28, 419, 'Logarithmic bar lengths; labels show measured values. Each panel uses its own scale.', 12), text(28, 440, 'Same two files, five batches of 1,000 calls. Lower is better; excludes I/O and process startup.', 12)]
    return svg('Native detection: before and after search optimization', 'The no-match signature scan improves; the section-match fast path is shown separately.', 465, parts)


def rpc_measurements():
    groups = defaultdict(list)
    pattern = r'BenchmarkRPCDecode/(base64|binary)_(\d+)KiB-\d+\s+\d+\s+([\d.]+) ns/op.*?([\d.]+) B/op\s+(\d+) allocs/op'
    for mode, size, latency, memory, allocations in re.findall(pattern, (DOCS / 'benchmarks/rpc.txt').read_text(encoding='utf-8')):
        groups[(mode, int(size))].append((float(latency), float(memory), int(allocations)))
    assert len(groups) == 4 and all(len(rows) == 5 for rows in groups.values()), 'Expected four RPC benchmark cases, each with five repeats'
    return {key: tuple(statistics.median(row[i] for row in rows) for i in range(3)) for key, rows in groups.items()}


def rpc_chart():
    metrics = rpc_measurements()
    parts = []
    for i, size in enumerate([64, 4096]):
        old = metrics[('base64', size)]
        new = metrics[('binary', size)]
        y = 110 + i * 130
        parts += [text(28, y, f'{size:,} KiB payload: allocations during response decode', 16, '#0f172a')]
        for j, (value, color, name) in enumerate([(old[1], COLORS['before'], 'Base64'), (new[1], COLORS['after'], 'Binary')]):
            row = y + 20 + j * 34
            parts += [text(28, row + 16, name, 12), box(100, row, log_width(value, old[1], 560), 23, color), text(685, row + 16, f'{value:,.0f} B/op', 13)]
    parts += [text(28, 379, 'Logarithmic bar lengths; labels show measured values. The existing response buffer is excluded.', 12), text(28, 400, 'This measures decode allocations only, not total memory, pipe throughput or end-to-end unpack speed.', 12)]
    return svg('Historical RPC SDK: decoding allocations', 'Former subprocess SDK; these measurements do not describe the current statically linked SDK.', 425, parts)


def overview_chart():
    before = {m['name']: m['median_ns'] for m in json.loads((DOCS / 'benchmarks/baseline.json').read_text(encoding='utf-8'))}
    after = {m['name']: m['median_ns'] for m in json.loads((DOCS / 'benchmarks/optimized.json').read_text(encoding='utf-8'))}
    codecs_before = {m['name']: m['median_ns'] for m in json.loads((DOCS / 'benchmarks/codecs-before.json').read_text(encoding='utf-8'))}
    codecs_after = {m['name']: m['median_ns'] for m in json.loads((DOCS / 'benchmarks/codecs-after.json').read_text(encoding='utf-8'))}
    rpc = rpc_measurements()
    panels = [
        ('01 / DETECTION', 'No-match PE scan', before['detect_plain_pe'] / 1000, after['detect_plain_pe'] / 1000, 'us', f"{before['detect_plain_pe'] / after['detect_plain_pe']:.1f}x", 'baseline / optimized latency'),
        ('02 / NATIVE DECODE', 'AP32 / 65 KiB', codecs_before['ap32_65kib'] / 1000, codecs_after['ap32_65kib'] / 1000, 'us', f"{codecs_before['ap32_65kib'] / codecs_after['ap32_65kib']:.1f}x", 'baseline / optimized latency'),
        ('03 / HISTORICAL RPC', '4 MiB response decode', rpc[('base64', 4096)][1], rpc[('binary', 4096)][1], 'B/op', f"{(1 - rpc[('binary', 4096)][1] / rpc[('base64', 4096)][1]) * 100:.3f}%", 'less allocated'),
    ]
    parts = []
    for i, (eyebrow, label, old, new, unit, ratio, caption) in enumerate(panels):
        x = 28 + i * 286
        parts += [box(x, 100, 272, 265, '#ffffff', 12), text(x + 18, 127, eyebrow, 11), text(x + 18, 157, label, 16, '#152e2b'), text(x + 18, 204, ratio, 34, COLORS['after']), text(x + 18, 226, caption, 12)]
        for j, (value, name, color) in enumerate([(old, 'Before', COLORS['before']), (new, 'After', COLORS['after'])]):
            y = 256 + j * 48
            number = f'{value:,.2f}' if unit == 'us' else f'{value:,.0f}'
            parts += [text(x + 18, y, name, 11), text(x + 254, y, f'{number} {unit}', 12, '#152e2b', 'end'), box(x + 18, y + 9, 236, 6, '#edf3ef', 3), box(x + 18, y + 9, log_width(value, old, 236), 6, color, 3)]
    parts += [text(28, 395, 'Apple M4 Pro / release Rust + Go benchmarks / median of five batches / lower is better.', 12), text(28, 416, 'Logarithmic bar lengths; labels show measured values. Excludes I/O, startup and end-to-end unpacking.', 12), text(28, 437, 'RPC allocation values are historical; the current cgo SDK copies Rust output into Go once.', 12)]
    return svg('Performance at a glance', 'Historical baseline vs recorded optimization results. Sources: docs/benchmarks/.', 459, parts)


def workflow_chart(formats):
    counts = Counter(f['support'] for f in formats)
    parts = [
        '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0 0L10 5L0 10" fill="none" stroke="#809891" stroke-width="1.5"/></marker></defs>',
        box(28, 170, 150, 118, '#e5efea', 12), text(46, 197, 'ENTRY POINTS', 11), text(46, 225, 'Rust API / CLI', 17, '#152e2b'), text(46, 250, 'Go SDK', 17, '#152e2b'), text(46, 272, 'cgo + Rust staticlib', 11),
        box(220, 170, 166, 118, '#152e2b', 12), text(238, 198, 'RUST CORE', 11, '#9ccdc0'), text(238, 229, 'Detect + iterate', 18, '#ffffff'), text(238, 255, 'Limits / layer history', 12, '#d2e5dc'), text(238, 275, 'Validate each result', 12, '#d2e5dc'),
        '<path d="M178 229H216M386 229H410M410 142V394" fill="none" stroke="#809891" stroke-width="1.5" marker-end="url(#arrow)"/>',
        box(730, 170, 142, 118, '#e5efea', 12), text(746, 198, 'RESULT', 11), text(746, 225, 'Bytes + history', 16, '#152e2b'), text(746, 251, 'Evidence / warnings', 11), text(746, 272, 'Typed errors', 11),
        '<path d="M702 142V394M702 229H726" fill="none" stroke="#809891" stroke-width="1.5" marker-end="url(#arrow)"/>',
    ]
    lanes = [
        (110, '#e1f1e8', '01  Native decoding', 'AP32 / GZIP / ZLIB / XZ / LZMA'),
        (194, '#e6edf3', '02  Official UPX backend', 'PE / ELF / Mach-O fixtures'),
        (278, '#fcf0df', '03  Static PE recovery', f"{counts['recovery']} families / explicit opt-in"),
        (362, '#ecf0f2', '04  Detection only', f"{counts['detect_only']} families / unsupported on unpack"),
    ]
    for y, color, title, detail in lanes:
        parts += [f'<path d="M410 {y + 32}H434M684 {y + 32}H702" fill="none" stroke="#809891" stroke-width="1.5" marker-end="url(#arrow)"/>', box(438, y, 246, 64, color, 10), text(454, y + 25, title, 15, '#152e2b'), text(454, y + 46, detail, 11)]
    parts += [text(28, 468, 'Automatic mode repeats native / UPX layers; recovery stops after repair. Analyzed programs are never run.', 12), text(28, 490, 'LZMA-Alone needs explicit selection. UPX needs an installed executable; recovery does not promise runnable output.', 12)]
    return svg('How Unpack processes each layer', 'Rust API, CLI and statically linked Go SDK share the same core.', 514, parts)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--engine', help='Read live format metadata from this unpack executable')
    parser.add_argument('--check', action='store_true', help='Fail if checked-in artifacts differ')
    args = parser.parse_args()
    formats_path = DOCS / 'formats.json'
    formats = json.loads(subprocess.check_output([args.engine, 'formats'], text=True)) if args.engine else json.loads(formats_path.read_text(encoding='utf-8'))
    generated = {formats_path: json.dumps(formats, indent=2) + '\n'}
    generated.update({DOCS / 'charts' / name: content for name, content in {
        'support.svg': support_chart(formats), 'upx-fixtures.svg': fixture_chart(),
        'native-detection.svg': native_chart(), 'sdk-allocations.svg': rpc_chart(),
        'ap32-decode.svg': codec_chart(),
        'overview.svg': overview_chart(), 'workflow.svg': workflow_chart(formats),
    }.items()})
    labels = json.loads((ROOT / 'scripts/chart_labels_zh.json').read_text(encoding='utf-8'))
    generated.update({path.with_stem(path.stem + '-zh'): chinese_svg(content, labels)
                      for path, content in list(generated.items()) if path.suffix == '.svg'})
    generated[DOCS / 'assets/hero-zh.svg'] = chinese_svg((DOCS / 'assets/hero.svg').read_text(encoding='utf-8'), labels)
    stale = []
    for path, content in generated.items():
        if args.check:
            if not path.is_file() or path.read_text(encoding='utf-8') != content:
                stale.append(str(path.relative_to(ROOT)))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding='utf-8')
    if stale:
        raise SystemExit('Stale generated artifacts: ' + ', '.join(stale))
    print(('Verified' if args.check else 'Generated') + f' {len(generated)} metadata/chart files')


if __name__ == '__main__':
    main()
