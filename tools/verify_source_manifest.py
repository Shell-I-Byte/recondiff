#!/usr/bin/env python3
"""Verify byte integrity and inventory of a pristine ReconDiff source checkout.

This verifies internal consistency, NOT GitHub publisher identity or provenance.
Run before builds/tests create untracked files. Standard library only.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

MANIFEST = 'SOURCE_MANIFEST_SHA256.json'
MAX_MANIFEST_SIZE = 1 << 20
MAX_SOURCE_FILE_SIZE = 16 << 20
MAX_FILES = 5000


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON manifest key: ' + key)
        result[key] = value
    return result


def valid_path(value):
    if not isinstance(value, str) or not value or '\\' in value or '\x00' in value:
        return False
    p = PurePosixPath(value)
    return (not p.is_absolute() and str(p) == value and
            all(s not in ('', '.', '..', '.git') for s in value.split('/')) and
            value != MANIFEST)


def files_under(root):
    found = {}
    for directory, subdirs, filenames in os.walk(root, followlinks=False):
        dp = Path(directory)
        if dp != root and dp.is_symlink():
            raise ValueError('symlinked source directory: ' + str(dp.relative_to(root)))
        for name in subdirs[:]:
            if name == '.git' and dp == root:
                subdirs.remove(name)
                continue
            if (dp / name).is_symlink():
                raise ValueError('symlinked source directory: ' + str((dp / name).relative_to(root)))
        for name in filenames:
            p = dp / name
            rel = p.relative_to(root).as_posix()
            if rel == MANIFEST:
                continue
            if not valid_path(rel):
                raise ValueError('unsafe source inventory path: ' + rel)
            mode = p.lstat().st_mode
            if not stat.S_ISREG(mode):
                raise ValueError('nonregular source file: ' + rel)
            found[rel] = p
            if len(found) > MAX_FILES:
                raise ValueError('too many source files')
    return found


def verify(root):
    root = Path(root).resolve(strict=True)
    mf = root / MANIFEST
    stat_before = mf.lstat()
    if not stat.S_ISREG(stat_before.st_mode) or stat_before.st_size > MAX_MANIFEST_SIZE:
        raise ValueError('manifest must be small regular file')
    raw = mf.read_bytes()
    if len(raw) > MAX_MANIFEST_SIZE:
        raise ValueError('oversized source manifest')
    manifest = json.loads(raw, object_pairs_hook=unique_pairs)
    if not isinstance(manifest, dict) or manifest.get('algorithm') != 'SHA-256':
        raise ValueError('invalid manifest algorithm')
    expected = manifest.get('files')
    declared = manifest.get('file_count')
    if not isinstance(expected, dict) or type(declared) is not int or declared != len(expected) or not 1 <= declared <= MAX_FILES:
        raise ValueError('manifest file count invalid')
    if any(not valid_path(key) or not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value)
           for key, value in expected.items()):
        raise ValueError('unsafe path or malformed SHA-256 in manifest')
    # Executable metadata is stored in the sealed manifest so that unzipping with
    # tools which discard POSIX mode bits does not change the next sealed ZIP.
    executable = manifest.get('executable_files', [])
    if (not isinstance(executable, list) or
            any(not isinstance(item, str) or not valid_path(item) or item not in expected
                for item in executable) or
            len(executable) != len(set(executable)) or
            executable != sorted(executable)):
        raise ValueError('invalid executable file inventory')
    actual = files_under(root)
    missing, extra = sorted(set(expected) - set(actual)), sorted(set(actual) - set(expected))
    if missing or extra:
        raise ValueError('source inventory differs: missing='+repr(missing[:10])+' extra='+repr(extra[:10]))
    for key in sorted(expected):
        p = actual[key]
        st_before = p.lstat()
        if st_before.st_size > MAX_SOURCE_FILE_SIZE:
            raise ValueError('source file oversized: '+key)
        with p.open('rb') as f:
            raw_file = f.read(MAX_SOURCE_FILE_SIZE + 1)
        st_after = p.lstat()
        if len(raw_file) > MAX_SOURCE_FILE_SIZE or (st_before.st_dev, st_before.st_ino,
            st_before.st_size, st_before.st_mtime_ns, st_before.st_ctime_ns) != (
            st_after.st_dev, st_after.st_ino, st_after.st_size,
            st_after.st_mtime_ns, st_after.st_ctime_ns):
            raise ValueError('source changed/oversized during read: '+key)
        if hashlib.sha256(raw_file).hexdigest() != expected[key]:
            raise ValueError('source SHA-256 mismatch: '+key)
    return {'status':'PASS', 'file_count':len(actual),
            'manifest_sha256':hashlib.sha256(raw).hexdigest(),
            'scope':'local content consistency; not publisher authentication'}


if __name__ == '__main__':
    try:
        print(json.dumps(verify(Path(__file__).resolve().parents[1]), sort_keys=True))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print('SOURCE_MANIFEST_REJECT: '+str(exc), file=sys.stderr)
        sys.exit(1)
