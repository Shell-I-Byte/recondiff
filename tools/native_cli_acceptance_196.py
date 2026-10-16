#!/usr/bin/env python3
"""Portable offline acceptance of the *native* compiled ReconDiff executable.

The command makes no network requests, operates on synthetic fixtures, and
requires positive, negative, privacy and deterministic controls to pass.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CANARY = 'SYNTHETIC_PRIVATE_CANARY_196_DONT_PRINT'


def check(ok, description):
    if not ok:
        raise AssertionError(description)
    print('PASS', description)


def run(binary, *args):
    return subprocess.run([str(binary), *map(str, args)], capture_output=True,
                          timeout=15, check=False)


def main():
    if len(sys.argv) != 2:
        raise SystemExit('Usage: python tools/native_cli_acceptance_196.py /path/to/compiled-cli')
    binary = Path(sys.argv[1]).resolve(strict=True)
    fixtures = ROOT / 'examples'
    before = fixtures / 'before.json'
    after = fixtures / 'after.json'
    scope = fixtures / 'scope.json'

    version = run(binary, '--version')
    check(version.returncode == 0 and version.stdout.strip() == b'recondiff 0.1.0-rc16',
          'native version matches sealed source')

    ok = run(binary, '--before', before, '--after', before, '--scope', scope, '--authorized')
    check(ok.returncode == 0, 'identical authorized snapshots exit 0')
    report = json.loads(ok.stdout)
    check(report['schema'] == 'recondiff.result/v1' and report['changes'] == [],
          'identical result has current schema and zero changes')

    diffs = [run(binary, '--before', before, '--after', after, '--scope', scope, '--authorized')
             for _ in range(4)]
    check(all(x.returncode == 2 for x in diffs), 'legitimate changed snapshots exit 2')
    check(all(x.stdout == diffs[0].stdout for x in diffs),
          'deterministic report bytes across four native runs')
    diff_report = json.loads(diffs[0].stdout)
    check(diff_report['summary']['modified'] == 1 and len(diff_report['changes']) >= 1,
          'real changed finding reported')
    check(b'never-echo' not in diffs[0].stdout and b'PRIVATE=secret' not in diffs[0].stdout,
          'no synthetic query/cookie secrets in evidence output')

    unauthorized = run(binary, '--before', before, '--after', after, '--scope', scope)
    check(unauthorized.returncode == 1 and not unauthorized.stdout,
          'no --authorized fails closed')

    with tempfile.TemporaryDirectory(prefix='recondiff-native196-') as d:
        bogus = Path(d) / 'invalid.json'
        bogus.write_text('{"schema":"recondiff.snapshot/v1","assets":[],"'+CANARY+'":1}', encoding='utf-8')
        bad = run(binary, '--before', bogus, '--after', after, '--scope', scope, '--authorized')
        check(bad.returncode == 1 and not bad.stdout,
              'malformed snapshot fails closed')
        check(CANARY.encode() not in bad.stderr, 'malformed field name not printed to stderr')

        protected = Path(d) / 'before.json'
        original = before.read_bytes()
        protected.write_bytes(original)
        wrong = run(binary, '--before', protected, '--after', after,
                    '--scope', scope, '--authorized', '--output', protected)
        check(wrong.returncode == 1 and protected.read_bytes() == original,
              'output cannot overwrite source input')
    print('NATIVE_CLI_ACCEPTANCE_196 PASS')

if __name__ == '__main__':
    main()
