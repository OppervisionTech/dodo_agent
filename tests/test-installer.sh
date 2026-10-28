#!/usr/bin/env bash
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
source "$repo/get.sh"
parse_args --version=v1.2.3 --api-key="dodo_$(printf '%064d' 0)" --endpoint=grpc.example.test:443 --enrollment-endpoint=https://api.example.test/v1/enroll
validate_inputs
[[ "$DODO_VERSION" == v1.2.3 && "$DODO_ENDPOINT" == grpc.example.test:443 ]]
if (parse_args --unknown=value) >/dev/null 2>&1; then echo 'unknown flag accepted' >&2; exit 1; fi
if (parse_args --endpoint) >/dev/null 2>&1; then echo 'missing value accepted' >&2; exit 1; fi
if (DODO_ENROLLMENT_ENDPOINT=http://example.test/v1/enroll; validate_inputs) >/dev/null 2>&1; then echo 'plaintext enrollment accepted' >&2; exit 1; fi
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT
printf 'synthetic release archive\n' > "$fixture/download.tar.gz"
sha256sum "$fixture/download.tar.gz" | sed 's#  .*#  aegis-agent-linux-amd64.tar.gz#' > "$fixture/check.sha256"
verify_checksum "$fixture/download.tar.gz" "$fixture/check.sha256"
printf corrupt >> "$fixture/download.tar.gz"
if (verify_checksum "$fixture/download.tar.gz" "$fixture/check.sha256") >/dev/null 2>&1; then echo 'corrupt archive accepted' >&2; exit 1; fi
cmp "$repo/get.sh" "$repo/scripts/install.sh"
echo INSTALLER_CONTRACT_OK
