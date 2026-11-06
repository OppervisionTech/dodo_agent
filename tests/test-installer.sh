#!/usr/bin/env bash
# Contract tests for the public installer (get.sh). Sources it without running
# main, then checks argument parsing, input validation and checksum handling.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../get.sh
source "$repo/get.sh" </dev/null

fail() { echo "FAIL: $*" >&2; exit 1; }

# Both "--flag value" and "--flag=value" forms parse.
parse_args --mode server --version=v1.2.3 --endpoint=grpc.example.test:443 \
  --enrollment-endpoint https://api.example.test/v1/enroll --non-interactive
validate_inputs
[[ "$DODO_MODE" == server && "$DODO_VERSION" == v1.2.3 ]] || fail 'flags not parsed'
[[ "$DODO_ENDPOINT" == grpc.example.test:443 ]] || fail 'endpoint not parsed'
[[ "$DODO_ENROLLMENT_ENDPOINT" == https://api.example.test/v1/enroll ]] || fail 'enrollment endpoint not parsed'
[[ "$DODO_NON_INTERACTIVE" == true ]] || fail '--non-interactive not parsed'

# Rejections run in subshells: error() exits.
(parse_args --unknown=value) >/dev/null 2>&1 && fail 'unknown flag accepted'
(parse_args --endpoint) >/dev/null 2>&1 && fail 'missing value accepted'
(parse_args --endpoint --non-interactive) >/dev/null 2>&1 && fail 'flag taken as a value'
(DODO_ENROLLMENT_ENDPOINT=http://example.test/v1/enroll; validate_inputs) >/dev/null 2>&1 \
  && fail 'plaintext enrollment accepted'
(DODO_MODE=desktop; validate_inputs) >/dev/null 2>&1 && fail 'unknown mode accepted'
(DODO_ENDPOINT='grpc.example.test'; validate_inputs) >/dev/null 2>&1 && fail 'endpoint without port accepted'
(parse_args --help) | grep -q -- "--mode server|k8s|dev" || fail "--help does not print usage"

# Checksum is fail-closed and reads only the hash from the .sha256 file.
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT
printf 'synthetic release archive\n' > "$fixture/download.tar.gz"
sha256sum "$fixture/download.tar.gz" | sed 's#  .*#  aegis-agent-linux-amd64.tar.gz#' > "$fixture/check.sha256"
verify_checksum "$fixture/download.tar.gz" "$fixture/check.sha256"
printf corrupt >> "$fixture/download.tar.gz"
(verify_checksum "$fixture/download.tar.gz" "$fixture/check.sha256") >/dev/null 2>&1 && fail 'corrupt archive accepted'
printf 'not-a-hash  x\n' > "$fixture/bad.sha256"
(verify_checksum "$fixture/download.tar.gz" "$fixture/bad.sha256") >/dev/null 2>&1 && fail 'malformed checksum accepted'

echo INSTALLER_CONTRACT_OK
