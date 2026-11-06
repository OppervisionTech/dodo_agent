#!/usr/bin/env python3
"""Package an approved staging image's ELF without publishing a release."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import tarfile
import tomllib


def build(binary: Path, source_sha: str, image: str, image_revision: str, run_id: str, output: Path):
    if not re.fullmatch(r'[a-f0-9]{40}', source_sha) or image_revision != source_sha:
        raise ValueError('image revision must match the checked out source SHA')
    if not re.fullmatch(r'ghcr\.io/oppervisiontech/aegis-agent@sha256:[a-f0-9]{64}', image):
        raise ValueError('staging image must be pinned to the canonical repository digest')
    if not re.fullmatch(r'[1-9][0-9]*', run_id):
        raise ValueError('a real Actions run ID is required')
    data = binary.read_bytes()
    if len(data) < 64 or len(data) > 256 * 1024 * 1024:
        raise ValueError('invalid binary size')
    if data[:6] != b'\x7fELF\x02\x01' or int.from_bytes(data[18:20], 'little') != 62:
        raise ValueError('only Linux amd64 ELF binaries belong in this staging bundle')
    if int.from_bytes(data[16:18], 'little') not in (2, 3):
        raise ValueError('ELF must be executable or position independent executable')
    root = Path(__file__).resolve().parents[1]
    version = tomllib.loads((root / 'Cargo.toml').read_text())['workspace']['package']['version']
    output.mkdir(parents=True, exist_ok=False)
    archive = output / 'aegis-agent-linux-amd64.tar.gz'
    # Reproducible archive bytes: source binary content owns the checksum.
    with archive.open('wb') as destination:
        with gzip.GzipFile(fileobj=destination, mode='wb', filename='', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w') as package:
                info = tarfile.TarInfo('aegis-agent')
                info.size, info.mode, info.mtime = len(data), 0o755, 0
                package.addfile(info, io.BytesIO(data))
    shutil.copyfile(root / 'get.sh', output / 'get.sh')
    assets = {}
    for artifact in [archive, output / 'get.sh']:
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        assets[artifact.name] = {'sha256': digest, 'bytes': artifact.stat().st_size}
        (output / (artifact.name + '.sha256')).write_text(f'{digest}  {artifact.name}\n')
    metadata = {
        'schemaVersion': 1, 'environment': 'staging', 'sourceRevision': source_sha,
        'image': image, 'imageRevision': image_revision, 'sourceVersion': version,
        'actionsRunId': run_id, 'assets': assets, 'manifestReady': False,
        'blockingRequirements': [
            'customer-accessible Dodo download channel must be approved and tested',
            'canonical get.sh currently requires matching versioned GitHub release assets',
            'the source repository is private; Actions artifacts are operator-only',
        ],
    }
    (output / 'distribution-candidate.json').write_text(json.dumps(metadata, indent=2) + '\n')
    files = sorted(p for p in output.iterdir() if not p.name.endswith('.sha256'))
    (output / 'checksums.sha256').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in files))
    return metadata


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ['binary', 'source-sha', 'image', 'image-revision', 'run-id', 'output']:
        parser.add_argument('--' + option, required=True)
    args = parser.parse_args()
    build(Path(args.binary), args.source_sha, args.image, args.image_revision, args.run_id, Path(args.output))
