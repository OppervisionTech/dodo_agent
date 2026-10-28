# Agent distribution and local SDK contract

Publish a reviewed release before enabling its portal installation manifest. Do
not configure an unpublished version or assume the container package is public.
The release workflow now tests an anonymous pull of the exact published image
before creating the GitHub release. Repository: `OppervisionTech/dodo_agent`;
image: `ghcr.io/oppervisiontech/aegis-agent:<semver without v>`.

The canonical installer is `get.sh` (also published byte-for-byte as `install.sh`).
Its URL is `https://github.com/OppervisionTech/dodo_agent/releases/download/<tag>/get.sh`.
Linux standard archives are `aegis-agent-linux-{amd64,arm64}.tar.gz`; lite archives
are `aegis-agent-lite-{amd64,arm64}.tar.gz`. Every archive requires a matching
SHA256 asset. Unknown flags, missing version/endpoints, non-HTTPS enrollment,
invalid keys and failed integrity checks fail before changing the service.

Pass the selected environment's **two independent** endpoints:

```sh
# Environment values come from the reviewed deployment installation manifest.
# DODO_API_KEY must be set without shell tracing; never commit it.
sudo -E bash get.sh --version "$DODO_AGENT_VERSION" \
  --endpoint "$DODO_ENDPOINT" \
  --enrollment-endpoint "$DODO_ENROLLMENT_ENDPOINT"
```

State and identity live in `/var/lib/aegis`, including protected `certs/`.
Enrollment reuses the persisted P256 key. Token refresh sends a timestamped,
ASN.1 ECDSA/SHA256 signature over `dodo-token-refresh\n<agent_id>\n<timestamp>`
(no trailing newline), plus a CSR for the same key. Deploy with the ingestor's
matching proof verifier. Keep `/etc/aegis/agent.env` root-readable and configuration
read-only to the service. Existing legacy certificates are copied on upgrade
only when the destination is absent; agent_id and buffers remain in place.

## Local application contract

- Native SDK gRPC: `/dodo.proto.v1.IngestorService/SubmitBatch` on loopback 4317.
- Native SDK HTTP: protobuf `SubmitBatchRequest`/`SubmitBatchResponse` at
  `POST http://127.0.0.1:4318/v1/batch`, `application/x-protobuf`.
- Standard OTLP Export services remain on 4317; OTLP HTTP protobuf remains at
  `/v1/traces`, `/v1/metrics`, `/v1/logs` on 4318. OTLP/JSON is not implemented.
- SDK identity is discarded. The enrolled agent stamps identity on upstream
  envelopes. Applications may send metric, log, trace, event and custom-event
  signals, never agent heartbeat/inventory/security. Current SDK health events
  use custom-event payloads.
- Maximum request 4MiB, native batch 1000 items, native payload 1MiB uncompressed.
  Always check accepted/rejected counts. Never blindly retry a partial ack.
- OTLP admission is atomic for each request: on saturation nothing is accepted
  and the receiver returns gRPC ResourceExhausted / HTTP429; exporters may retry.
- `/healthz` checks the local HTTP process; `/readyz` checks queue availability.
  Neither proves backend enrollment, delivery or storage.

The receiver remains loopback-only. Docker installer mode is Linux host-network
only and persists `/var/lib/aegis` in `dodo-agent-data`. It does not publish
container ports which cannot reach the container's loopback. Docker Desktop,
Kubernetes and managed application hosting require their own supported deployment
manifest and are rejected by this installer instead of claiming successful setup.
Remote plaintext telemetry is rejected. No app should point OTLP at the native
Dodo gateway or bypass the agent.

## Verification

Run `bash tests/test-installer.sh`, `cargo fmt --all -- --check`, then the workspace
tests on Linux. For a portable local integration build:

```sh
CARGO_BUILD_JOBS=2 cargo build --no-default-features --features otel
# Build examples/receiver-smoke in the matching Go SDK.
python3 tests/receiver-smoke.py --binary target/debug/aegis-agent \
  --python-sdk /path/to/dodo_sdk_python --go-client /path/to/go-receiver-smoke
```

This smoke uses the actual SDK clients, actual agent receiver/batcher/transport
and a synthetic local upstream. It does not certify Kong, Kafka, workers, tenant
storage, Linux systemd sandbox, multiarchitecture containers or public release
availability; those remain release/environment checks.

## Durable delivery semantics
Disk replay peeks records without deleting them, then acknowledges only after an
upstream response with valid accepted/rejected counts. Failed calls retain records;
a five-second retry tick recovers without restarting. New writes are unique atomic
files; legacy appended records preserve their unconsumed tail. Replay of persisted records is at least
once: a crash after upstream acceptance but before local ACK may replay a duplicate.
An explicit rejection is counted as failed and is not retried as a partial batch.
Corrupt local records remain on disk for diagnosis. Native capacity errors return
ResourceExhausted/HTTP429; SDKs report drops if their retry budget is exhausted.
