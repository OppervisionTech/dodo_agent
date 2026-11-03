"""Execute the actual release packaging steps with synthetic Cargo outputs."""
from pathlib import Path
import re
import os
import subprocess
import tarfile
import tempfile
import tomllib
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / '.github/workflows/release.yml').read_text()


def packaging_step(kind):
    match = re.search(rf'      - name: Package binary \({kind}\).*?        run: \|\n(.*?)(?=\n      - )', WORKFLOW, re.S)
    if not match:
        raise AssertionError(f'missing {kind} packaging step')
    return '\n'.join(line[10:] for line in match[1].splitlines())


class ReleaseContracts(unittest.TestCase):
    def test_exclusive_feature_builds_disable_defaults(self):
        commands = [line.strip() for line in WORKFLOW.splitlines() if 'run: cargo build ' in line or 'run: cross build ' in line]
        self.assertEqual(len(commands), 2)
        for command in commands:
            self.assertIn('--locked', command)
            self.assertIn('--no-default-features', command)
            self.assertIn('--features ${{ matrix.variant }}', command)

    def test_real_packaging_steps_use_actual_cargo_binary(self):
        bins = tomllib.loads((ROOT / 'Cargo.toml').read_text())['bin']
        self.assertEqual([binary['name'] for binary in bins], ['aegis-agent'])
        for variant, kind, source, destination, target in [
            ('linux', 'tar', 'aegis-agent', 'aegis-agent', 'x86_64-unknown-linux-musl'),
            ('lite', 'tar', 'aegis-agent', 'aegis-agent-lite', 'x86_64-unknown-linux-musl'),
            ('windows', 'zip', 'aegis-agent.exe', 'aegis-agent.exe', 'x86_64-pc-windows-gnu'),
        ]:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                binary = root / 'target' / target / 'release' / source
                binary.parent.mkdir(parents=True)
                binary.write_bytes(b'synthetic executable\n')
                command = packaging_step(kind)
                values = dict(variant=variant, arch='amd64', target=target, source_binary=source, binary=destination)
                for name, value in values.items():
                    command = command.replace('${{ matrix.' + name + ' }}', value)
                subprocess.run(['bash', '-euo', 'pipefail', '-c', command], cwd=root, check=True, capture_output=True, env={**os.environ, 'COPYFILE_DISABLE': '1'})
                extension = 'tar.gz' if kind == 'tar' else 'zip'
                name = f'aegis-agent-{variant}-amd64.{extension}'
                archive = root / 'dist' / name
                if kind == 'tar':
                    with tarfile.open(archive) as package:
                        self.assertEqual(package.getnames(), [destination])
                else:
                    with zipfile.ZipFile(archive) as package:
                        self.assertEqual(package.namelist(), [destination])
                subprocess.run(['sha256sum', '-c', name + '.sha256'], cwd=root / 'dist', check=True, capture_output=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
