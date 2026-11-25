#!/usr/bin/env python3
"""Build the Rust archive consumed by cgo for the selected Go target."""
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    ('darwin', 'arm64'): 'aarch64-apple-darwin',
    ('darwin', 'amd64'): 'x86_64-apple-darwin',
    ('linux', 'arm64'): 'aarch64-unknown-linux-gnu',
    ('linux', 'amd64'): 'x86_64-unknown-linux-gnu',
    ('windows', 'amd64'): 'x86_64-pc-windows-gnu',
}


def main():
    env = json.loads(subprocess.check_output(['go', 'env', '-json', 'GOOS', 'GOARCH', 'CGO_ENABLED'], text=True))
    pair = (env['GOOS'], env['GOARCH'])
    if env['CGO_ENABLED'] != '1':
        raise SystemExit('The Go SDK requires CGO_ENABLED=1 and a C compiler for the target.')
    target = TARGETS.get(pair)
    if target is None:
        raise SystemExit(f'Unsupported Go SDK target: {pair}')
    subprocess.run(['cargo', 'build', '--locked', '--release', '--lib', '--target', target], cwd=ROOT, check=True)
    # Cargo metadata resolves CARGO_TARGET_DIR and repository/global Cargo configuration.
    metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--no-deps', '--format-version=1'], cwd=ROOT, text=True))
    source = Path(metadata['target_directory']) / target / 'release' / 'libunpack.a'
    dest = ROOT / 'native' / '-'.join(pair) / 'libunpack.a'
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, dest)
    # Replacing an archive alone does not invalidate Go's package cache.
    subprocess.run(['go', 'clean', '-cache'], cwd=ROOT, check=True)
    print(f'Built {dest.relative_to(ROOT)}; run go build ./examples/go or go test ./...')


if __name__ == '__main__':
    main()
