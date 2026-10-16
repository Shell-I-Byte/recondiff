"""Archive-mode regression and falsification, including discarded POSIX modes."""
import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path
import tempfile
import unittest
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parent
S = importlib.util.spec_from_file_location('source_seal', ROOT/'seal_source.py')
# seal_source imports verify_source_manifest from its own tools directory.
import sys
sys.path.insert(0,str(ROOT))
sealer = importlib.util.module_from_spec(S)
S.loader.exec_module(sealer)

class SourceModeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='recondiff-modes-')
        self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name)
        self.src=self.base/'src'
        self.src.mkdir()
        (self.src/'scripts').mkdir()
        (self.src/'scripts'/'exec.py').write_bytes(b'print(1)\n')
        (self.src/'plain.txt').write_bytes(b'plain\n')
        self.set_manifest(['scripts/exec.py'])

    def set_manifest(self,exe):
        files={x.relative_to(self.src).as_posix():hashlib.sha256(x.read_bytes()).hexdigest()
               for x in self.src.rglob('*') if x.is_file() and x.name!='SOURCE_MANIFEST_SHA256.json'}
        manifest=dict(algorithm='SHA-256',file_count=len(files),files=files,executable_files=exe)
        (self.src/'SOURCE_MANIFEST_SHA256.json').write_text(json.dumps(manifest,sort_keys=True))

    def test_checkout_git_modes_match_manifest(self):
        checkout = ROOT.parent
        if not (checkout/'.git').exists():
            self.skipTest('sealed ZIP has no Git index; parity verified separately with bundle')
        run = subprocess.run(['git','-C',str(checkout),'ls-files','-s','-z'],
                             stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
        tracked = {}
        for record in run.stdout.split(b'\0'):
            if not record: continue
            header,path = record.split(b'\t',1)
            tracked[path.decode()] = header.split(b' ')[0].decode()
        manifest = json.loads((checkout/'SOURCE_MANIFEST_SHA256.json').read_text())
        self.assertEqual(set(tracked),set(manifest['files'])|{'SOURCE_MANIFEST_SHA256.json'})
        self.assertTrue(all(x in ('100644','100755') for x in tracked.values()))
        self.assertEqual(sorted(p for p,mode in tracked.items() if mode=='100755'),
                         manifest['executable_files'])

    def test_archive_executable_bit_matches_manifest(self):
        zpath=self.base/'one.zip'
        sealer.seal(zpath,self.src)
        with ZipFile(zpath) as z:
            root='ReconDiff_v0.1.0-rc16/'
            self.assertEqual(z.getinfo(root+'scripts/exec.py').external_attr>>16,0o100755)
            self.assertEqual(z.getinfo(root+'plain.txt').external_attr>>16,0o100644)
            self.assertEqual(z.getinfo(root+'SOURCE_MANIFEST_SHA256.json').external_attr>>16,0o100644)

    def test_roundtrip_without_executable_fs_mode(self):
        a,b=self.base/'one.zip',self.base/'two.zip'
        sealer.seal(a,self.src)
        with ZipFile(a) as z:z.extractall(self.base/'extracted')
        # Python's ZipFile.extractall is permitted to discard the +x bit.
        sealer.seal(b,self.base/'extracted'/'ReconDiff_v0.1.0-rc16')
        self.assertEqual(a.read_bytes(),b.read_bytes())

    def test_declared_unknown_executable_is_rejected(self):
        self.set_manifest(['scripts/missing.py'])
        with self.assertRaises(ValueError):
            sealer.seal(self.base/'bad.zip',self.src)

    def test_duplicate_executable_is_rejected(self):
        self.set_manifest(['scripts/exec.py','scripts/exec.py'])
        with self.assertRaises(ValueError):
            sealer.seal(self.base/'bad.zip',self.src)

    def test_unlisted_executable_defaults_not_executable(self):
        self.set_manifest([])
        path=self.base/'noexec.zip'
        sealer.seal(path,self.src)
        with ZipFile(path) as z:
            self.assertEqual(z.getinfo('ReconDiff_v0.1.0-rc16/scripts/exec.py').external_attr>>16,0o100644)

if __name__=='__main__': unittest.main()
