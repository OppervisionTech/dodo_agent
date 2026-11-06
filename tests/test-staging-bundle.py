import hashlib
import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('staging_bundle', ROOT / 'scripts/build-staging-bundle.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
SHA, IMAGE = 'a' * 40, 'ghcr.io/oppervisiontech/aegis-agent@sha256:' + 'b' * 64


class StagingBundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        header = bytearray(64)
        header[:6], header[16:18], header[18:20] = b'\x7fELF\x02\x01', (2).to_bytes(2, 'little'), (62).to_bytes(2, 'little')
        self.binary = self.root / 'binary'
        self.binary.write_bytes(header + b'synthetic artifact')

    def tearDown(self):
        self.temporary.cleanup()

    def test_staging_bundle_is_pinned_hashed_and_not_a_fake_customer_manifest(self):
        output = self.root / 'bundle'
        metadata = module.build(self.binary, SHA, IMAGE, SHA, '123', output)
        self.assertEqual(metadata['environment'], 'staging')
        self.assertEqual(metadata['image'], IMAGE)
        self.assertFalse(metadata['manifestReady'])
        self.assertNotIn('installerUrl', metadata)
        for name, asset in metadata['assets'].items():
            self.assertEqual(hashlib.sha256((output / name).read_bytes()).hexdigest(), asset['sha256'])
        with tarfile.open(output / 'aegis-agent-linux-amd64.tar.gz') as archive:
            self.assertEqual(archive.getnames(), ['aegis-agent'])
            self.assertEqual(archive.extractfile('aegis-agent').read(), self.binary.read_bytes())
        self.assertEqual(json.loads((output / 'distribution-candidate.json').read_text()), metadata)
        second = self.root / 'second'
        module.build(self.binary, SHA, IMAGE, SHA, '124', second)
        self.assertEqual((output / 'aegis-agent-linux-amd64.tar.gz').read_bytes(), (second / 'aegis-agent-linux-amd64.tar.gz').read_bytes())

    def test_wrong_image_revision_and_mutable_tags_are_rejected(self):
        with self.assertRaises(ValueError):
            module.build(self.binary, SHA, IMAGE, 'c' * 40, '123', self.root / 'wrong')
        with self.assertRaises(ValueError):
            module.build(self.binary, SHA, 'ghcr.io/oppervisiontech/aegis-agent:staging', SHA, '123', self.root / 'tag')

    def test_portable_mock_or_non_linux_binary_cannot_be_distributed(self):
        self.binary.write_bytes(b'mock binary' * 10)
        with self.assertRaises(ValueError):
            module.build(self.binary, SHA, IMAGE, SHA, '123', self.root / 'mock')


if __name__ == '__main__':
    unittest.main(verbosity=2)
