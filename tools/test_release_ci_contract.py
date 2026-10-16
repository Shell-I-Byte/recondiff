"""Offline CI/release guard: no network, no external dependencies."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / '.github/workflows/ci.yml'

class ReleaseCIContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = CI.read_text(encoding='utf-8')

    def test_supported_security_patch_versions(self):
        ci = self.workflow
        self.assertIn("'1.26.9'", ci)
        self.assertIn("'1.27.2'", ci)
        self.assertNotIn('1.26.8', ci)
        self.assertNotIn('1.27.1', ci)
        self.assertRegex(ci, r"matrix:\s*\n\s*go:\s*\['1\.26\.9', '1\.27\.2'\]")
        self.assertGreaterEqual(ci.count("go-version: '1.27.2'"), 2)

    def test_release_tag_and_pre_release_native_trigger(self):
        ci = self.workflow
        self.assertIn("tags: ['v1.*']", ci)
        native = ci.split('\n  native:', 1)[1]
        head = native.split('\n    strategy:', 1)[0]
        self.assertNotIn('if: github.event_name', head,
                         'Native runners must qualify PRs before a v1 tag is made')
        self.assertIn('needs: [test, quality]', head)
        for runner in ('ubuntu-24.04-arm', 'macos-15', 'windows-2025'):
            self.assertIn(runner, native)

    def test_reproducible_release_manifest_verification_is_in_ci(self):
        ci = self.workflow
        self.assertIn('python3 tools/verify_source_manifest.py', ci)
        self.assertLess(ci.index('python3 tools/verify_source_manifest.py'), ci.index('go test -count=1 ./...'))

    def test_randomized_tests_in_ci(self):
        self.assertIn('go test -shuffle=on -count=3 ./...', self.workflow)

    def test_sha_pinned_actions(self):
        ci = self.workflow
        uses = re.findall(r'^\s*- uses:\s*([^\s#]+)', ci, flags=re.M)
        self.assertGreaterEqual(len(uses), 6)
        for use in uses:
            self.assertRegex(use, r'^actions/[A-Za-z0-9_-]+@[0-9a-f]{40}$')

if __name__ == '__main__':
    unittest.main()
