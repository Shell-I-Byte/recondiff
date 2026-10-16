"""Positive and falsification controls for the source manifest verifier."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

S = importlib.util.spec_from_file_location('source_verify', Path(__file__).with_name('verify_source_manifest.py'))
v = importlib.util.module_from_spec(S)
S.loader.exec_module(v)

class SourceManifestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='recondiff-check-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root/'src').mkdir()
        (self.root/'src'/'code.go').write_bytes(b'package src\n')
        self.write_manifest()

    def write_manifest(self, overrides=None):
        files = {'src/code.go':hashlib.sha256(b'package src\n').hexdigest()}
        if overrides is not None:
            files.update(overrides)
        (self.root/v.MANIFEST).write_text(json.dumps({
            'algorithm':'SHA-256', 'source_version':'test',
            'file_count':len(files),'files':files}), encoding='utf8')

    def rejected(self):
        with self.assertRaises((ValueError, OSError, TypeError)):
            v.verify(self.root)

    def test_valid_source(self):
        self.assertEqual(v.verify(self.root)['file_count'], 1)

    def test_changed_source(self):
        (self.root/'src'/'code.go').write_bytes(b'package changed\n')
        self.rejected()

    def test_added_unlisted_file(self):
        (self.root/'src'/'unexpected').write_bytes(b'x')
        self.rejected()

    def test_missing_listed_file(self):
        (self.root/'src'/'code.go').unlink()
        self.rejected()

    def test_bad_hash(self):
        self.write_manifest({'src/code.go':'0'*64})
        self.rejected()

    def test_path_traversal(self):
        self.write_manifest({'../attack':'0'*64})
        self.rejected()

    def test_symlinked_file(self):
        (self.root/'src'/'code.go').unlink()
        (self.root/'src'/'code.go').symlink_to('/etc/hosts')
        self.rejected()

    def test_symlinked_directory(self):
        (self.root/'other').symlink_to('/tmp', target_is_directory=True)
        self.rejected()

    def test_duplicate_json_field(self):
        (self.root/v.MANIFEST).write_text('{"algorithm":"SHA-256","algorithm":"MD5"}', encoding='utf8')
        self.rejected()

    def test_case_changed_path(self):
        self.write_manifest({'SRC/code.go':'0'*64})
        self.rejected()

    def test_wrong_count(self):
        p=self.root/v.MANIFEST
        m=json.loads(p.read_text())
        m['file_count']=99
        p.write_text(json.dumps(m))
        self.rejected()

    def test_valid_executable_metadata(self):
        p=self.root/v.MANIFEST
        m=json.loads(p.read_text())
        m['executable_files']=['src/code.go']
        p.write_text(json.dumps(m))
        self.assertEqual(v.verify(self.root)['file_count'],1)

    def test_reject_invalid_executable_metadata(self):
        for value in (['unknown.sh'], ['src/code.go', 'src/code.go'],
                      ['../escape'], 'src/code.go', [42]):
            with self.subTest(value=value):
                self.write_manifest()
                p=self.root/v.MANIFEST
                m=json.loads(p.read_text())
                m['executable_files']=value
                p.write_text(json.dumps(m))
                self.rejected()

    def test_nonregular_source(self):
        (self.root/'src'/'socket').mkdir()
        (self.root/'src'/'socket'/'evil').symlink_to('/etc/hosts')
        self.rejected()

if __name__ == '__main__':
    unittest.main()
