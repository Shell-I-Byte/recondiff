"""Offline release-contract regression for mandatory native validation.

This is a workflow *structure* test. It is not proof that GitHub Actions ran.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / '.github/workflows/ci.yml'

class NativeReleaseGates196(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ci = CI.read_text('utf-8')
        cls.native = cls.ci.split('\n  native:', 1)[-1] if '\n  native:' in cls.ci else ''

    def test_three_required_real_native_runners(self):
        runner = self.native
        for os_name, goos, arch in (
            ('ubuntu-24.04-arm', 'linux', 'arm64'),
            ('macos-15', 'darwin', 'arm64'),
            ('windows-2025', 'windows', 'amd64'),
        ):
            self.assertRegex(runner, r'- os: '+re.escape(os_name)+r'\s+goos: '+goos+r'\s+goarch: '+arch)

    def test_native_build_race_vet_modules_and_cli_contract(self):
        native = self.native
        for required in (
            'go test -count=1 ./...',
            'go test -race -count=1 ./...',
            'go vet ./...',
            'go build ./...',
            'go mod verify',
            'go-version: \'1.27.2\'',
            'tools/native_cli_acceptance_196.py',
            'GOHOSTOS', 'GOHOSTARCH',
        ):
            self.assertIn(required, native)

    def test_native_is_not_tag_only_or_manual_only(self):
        head = self.native.split('\n    strategy:', 1)[0]
        self.assertNotIn("if: github.event_name == 'workflow_dispatch'", head,
                         'release candidate PRs must run native qualification before tagging v1')
        self.assertIn('needs: [test, quality]', head)

if __name__ == '__main__':
    unittest.main()
