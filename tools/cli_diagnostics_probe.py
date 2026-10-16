#!/usr/bin/env python3
"""Independent compiled-CLI privacy and log-injection regression; stdlib-only.
The test uses only local temporary files, no DNS or network access.
"""
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile

BIN = os.environ.get('RECONDIFF_BIN')
if not BIN:
    raise SystemExit('RECONDIFF_BIN is required (absolute path to compiled executable)')
BIN = str(Path(BIN).resolve())
CHECKS = 0

def check(label, ok, context=b''):
    global CHECKS
    if not ok:
        raise AssertionError(f'{label}: {context[:500]!r}')
    CHECKS += 1

def invoke(*args):
    return subprocess.run([BIN, *args], capture_output=True, timeout=8, check=False)

with tempfile.TemporaryDirectory(prefix='recondiff-052-') as directory:
    d = Path(directory)
    before, after, scope = (d / x for x in ('before.json', 'after.json', 'scope.json'))
    before.write_text('{"schema":"recondiff.snapshot/v1","assets":[]} "INJECT\\nJSON-LOG-SPOOF"')
    after.write_text('{"schema":"recondiff.snapshot/v1","assets":[]}')
    scope.write_text('{"schema":"recondiff.scope/v1","purpose":"Authorized local fixture","authorized_origins":["https://example.test"]}')
    inputs = ['--before', str(before), '--after', str(after), '--scope', str(scope), '--authorized']
    attacks = {
        'flag-newline': ['--BAD\nFLAG-LOG-SPOOF'],
        'flag-ansi': ['--BAD\x1b[2JSCREEN-CLEAR'],
        'flag-bidi': ['--BAD\u202eRIGHT-TO-LEFT'],
        'filename-newline': ['--before', str(d / 'missing\nFILE-LOG-SPOOF'), '--after', str(after), '--scope', str(scope), '--authorized'],
        'JSON-decoded-escape': inputs,
        'output-path-newline': ['--before', str(after), '--after', str(after), '--scope', str(scope), '--authorized', '--output', str(d / 'missing\nOUTPUT-LOG-SPOOF' / 'report.json')],
    }
    for name,args in attacks.items():
        result = invoke(*args)
        check(name+' rc', result.returncode == 1, result.stderr)
        check(name+' stderr-lines', result.stderr.count(b'\n') == 1, result.stderr)
        check(name+' stderr-escapes', b'\x1b' not in result.stderr and '\u202e'.encode('utf-8') not in result.stderr, result.stderr)
        check(name+' stdout-empty', not result.stdout, result.stdout)
    help_result = invoke('--help')
    check('help rc', help_result.returncode == 0, help_result.stderr)
    check('help options', b'-authorized' in help_result.stderr and b'-scope' in help_result.stderr, help_result.stderr)
    check('help stdout-empty', not help_result.stdout, help_result.stdout)
    ver = invoke('--version')
    check('version rc', ver.returncode == 0, ver.stderr)
    src = (Path(__file__).resolve().parents[1] / 'internal/diff/diff.go').read_text(encoding='utf-8')
    match = re.search(r'Version\s*=\s*"([^"]+)"', src)
    check('version source present', match is not None)
    check('version exact', ver.stdout == ('recondiff ' + match.group(1) + '\n').encode(), ver.stdout)
    before.write_text(after.read_text())
    good = invoke(*inputs)
    check('unchanged authorized rc', good.returncode == 0, good.stderr)
    report = json.loads(good.stdout)
    check('versioned result', report['schema'] == 'recondiff.result/v1' and report['changes'] == [], good.stdout)
    noauth = invoke(*inputs[:-1])
    check('unauthorized rc', noauth.returncode == 1, noauth.stderr)
    check('unauthorized no evidence', not noauth.stdout, noauth.stdout)

print(f'PASS {CHECKS}/{CHECKS} compiled native Linux CLI controls (no network)')
