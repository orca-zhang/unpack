#!/usr/bin/env python3
"""Capture real CLI output and render bilingual GIFs. Requires Pillow and official UPX."""
import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import tempfile

from PIL import Image, ImageDraw, ImageFont

ROOT = pathlib.Path(__file__).resolve().parents[1]
WIDTH, HEIGHT = 1040, 640
MINT, INK, MUTED = '#b6edcb', '#eaf4ed', '#a3bfb7'


def font(size, chinese=False):
    candidates = [
        '/System/Library/Fonts/Hiragino Sans GB.ttc' if chinese else '/System/Library/Fonts/Menlo.ttc',
        'C:/Windows/Fonts/msyh.ttc' if chinese else 'C:/Windows/Fonts/consola.ttf',
        '/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc' if chinese else '/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf',
    ]
    for path in candidates:
        if pathlib.Path(path).is_file():
            return ImageFont.truetype(path, size)
    raise SystemExit('Install a monospace font and a Chinese font (for example DejaVu Sans Mono + Noto Sans CJK).')


def record(engine):
    manifest = json.loads((ROOT / 'testdata/payloads/manifest.json').read_text(encoding='utf-8'))
    sample = next(s for s in manifest['samples'] if s['name'] == 'gzip-xz-upx')
    checksum = shutil.which('shasum') or shutil.which('sha256sum')
    if not checksum:
        raise SystemExit('Install shasum or sha256sum to record the checksum command.')
    checksum_args = ['-a', '256'] if pathlib.Path(checksum).stem == 'shasum' else []
    with tempfile.TemporaryDirectory(prefix='unpack-demo-') as temporary:
        work = pathlib.Path(temporary)
        for source, name, digest in [(sample['packed'], 'sample.packed', sample['packed_sha256']),
                                     (sample['unpacked'], 'expected.exe', sample['unpacked_sha256'])]:
            content = (ROOT / 'testdata/payloads' / source).read_bytes()
            assert hashlib.sha256(content).hexdigest() == digest, f'Fixture hash mismatch: {source}'
            (work / name).write_bytes(content)
        commands = [
            ('unpack detect sample.packed', [str(engine), 'detect', 'sample.packed']),
            ('unpack unpack -o restored.exe sample.packed', [str(engine), 'unpack', '-o', 'restored.exe', 'sample.packed']),
            (' '.join([pathlib.Path(checksum).name, *checksum_args, 'restored.exe', 'expected.exe']),
             [checksum, *checksum_args, 'restored.exe', 'expected.exe']),
        ]
        stages = []
        for display, command in commands:
            result = subprocess.run(command, cwd=work, capture_output=True, text=True, check=True, timeout=45)
            stages.append((display, result.stdout.rstrip().splitlines()))
        assert (work / 'restored.exe').read_bytes() == (work / 'expected.exe').read_bytes(), 'Decoded bytes differ'
        layers = [line.split(': ', 1)[1].split()[0] for line in stages[1][1] if line.startswith('Layer ')]
        assert layers == sample['history'], f'Unexpected layer history: {layers}'
        assert all(line.split()[0] == sample['unpacked_sha256'] for line in stages[2][1]), 'Checksum output differs'
        version = subprocess.check_output([str(engine), 'version'], text=True).strip()
    return stages, version


def render(stages, version, language):
    chinese = language == 'zh'
    terminal_font, label_font, title_font = font(18), font(16, chinese), font(28, chinese)
    labels = ['识别外层格式', '逐层解包', '校验解包结果'] if chinese else ['Detect the outer format', 'Unpack every layer', 'Verify the result']
    title = 'Unpack 实际演示' if chinese else 'Unpack in action'
    success = '逐字节一致 · SHA-256 校验通过' if chinese else 'Byte-for-byte match · SHA-256 verified'
    footer = '真实命令输出 · 演示节奏经调整' if chinese else 'Real CLI output · Playback timing adjusted'
    frames, durations, transcript = [], [], []

    def frame(stage, lines, typing='', cursor=False, verified=False, duration=100):
        canvas = Image.new('RGB', (WIDTH, HEIGHT), '#f5f9f7')
        draw = ImageDraw.Draw(canvas)
        draw.text((26, 18), title, font=title_font, fill='#152e2b')
        draw.text((28, 57), f'0{stage + 1} / {labels[stage]}', font=label_font, fill='#157d70')
        draw.text((720, 33), 'GZIP > XZ > UPX > PE', font=terminal_font, fill='#526966')
        draw.rounded_rectangle((16, 92, 1024, 552), radius=16, fill='#0d2428')
        for x, color in [(42, '#b87960'), (64, '#d5b36b'), (86, '#79bd94')]:
            draw.ellipse((x, 113, x + 10, 123), fill=color)
        draw.text((432, 108), version, font=label_font, fill=MUTED)
        draw.line((34, 140, 1006, 140), fill='#28483f')
        visible = lines + ([('$ ' + typing, INK)] if typing or cursor else [])
        for index, (line, color) in enumerate(visible):
            assert terminal_font.getlength(line) < WIDTH - 76, f'Terminal line would be clipped: {line}'
            assert index < 13, 'Transcript no longer fits the terminal'
            draw.text((38, 158 + index * 28), line, font=terminal_font, fill=color)
        if cursor:
            x = 38 + terminal_font.getlength('$ ' + typing)
            y = 162 + (len(visible) - 1) * 28
            draw.rectangle((x + 2, y, x + 10, y + 18), fill=MINT)
        if verified:
            draw.rounded_rectangle((26, 571, 1014, 619), radius=10, fill='#e0f0e5')
            draw.text((44, 585), success, font=label_font, fill='#157d70')
        else:
            draw.text((28, 582), footer, font=label_font, fill='#526966')
        frames.append(canvas)
        durations.append(duration)

    for index, (command, output) in enumerate(stages):
        frame(index, transcript, cursor=True, duration=600)
        for length in range(4, len(command), 4):
            frame(index, transcript, typing=command[:length], cursor=True, duration=85)
        frame(index, transcript, typing=command, cursor=True, duration=300)
        transcript.append(('$ ' + command, MINT))
        for line in output:
            transcript.append((line, MINT if line.startswith('Layer ') else MUTED))
            frame(index, transcript, duration=350)
        frame(index, transcript, duration=1300 if index < 2 else 4200, verified=index == 2)
        transcript.append(('', MUTED))
    palette = frames[-1].quantize(colors=128)
    frames = [image.quantize(palette=palette, dither=Image.Dither.NONE) for image in frames]
    destination = ROOT / 'docs/assets' / ('demo-zh.gif' if chinese else 'demo.gif')
    frames[0].save(destination, save_all=True, append_images=frames[1:], duration=durations,
                   loop=0, optimize=True, disposal=1,
                   comment=b'Real CLI capture; output and fixture SHA-256 verified. Playback timing adjusted.')
    with Image.open(destination) as animation:
        total = 0
        for index in range(animation.n_frames):
            animation.seek(index)
            total += animation.info['duration']
        print(f'{destination.relative_to(ROOT)}: {animation.n_frames} frames, {total / 1000:.1f}s, {destination.stat().st_size / 1024:.0f} KiB')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', type=pathlib.Path, default=ROOT / 'target/release/unpack')
    args = parser.parse_args()
    stages, version = record(args.engine.resolve())
    for language in ('en', 'zh'):
        render(stages, version, language)


if __name__ == '__main__':
    main()
