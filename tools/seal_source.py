#!/usr/bin/env python3
"""Deterministic source ZIP from a pristine, verified ReconDiff checkout.

The source integrity manifest is not a publisher signature. This is a
reproducible packaging step; independent recipients must separately verify
SHA256SUMS against an authenticated publisher channel.
"""
import json
import os
from pathlib import Path
import sys
import zipfile

sys.dont_write_bytecode = True
from verify_source_manifest import verify


def seal(destination, source):
    source = Path(source).resolve(strict=True)
    destination = Path(destination).resolve()
    if destination == source or source in destination.parents:
        raise ValueError('release output must be outside the source directory')
    checked = verify(source)
    manifest = json.loads((source / 'SOURCE_MANIFEST_SHA256.json').read_text('utf-8'))
    files = sorted([*manifest['files'], 'SOURCE_MANIFEST_SHA256.json'])
    executable = set(manifest.get('executable_files', []))
    entries = [source / x for x in files]
    prefix = 'ReconDiff_v0.1.0-rc16'
    tmp = destination.with_suffix(destination.suffix + '.part')
    try:
        with zipfile.ZipFile(tmp, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9, strict_timestamps=True) as z:
            for rel, local in zip(files, entries):
                info = zipfile.ZipInfo(prefix + '/' + rel, date_time=(1980,1,1,0,0,0))
                info.create_system = 3
                info.external_attr = ((0o100755 if rel in executable else 0o100644) << 16)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.flag_bits = 0x800
                z.writestr(info, local.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        os.replace(tmp, destination)
    finally:
        tmp.unlink(missing_ok=True)
    print(f'PASS sealed {len(files)} source entries; {checked["file_count"]} matched manifest')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Usage: python3 tools/seal_source.py /outside/source.zip')
    seal(sys.argv[1], Path(__file__).resolve().parents[1])
