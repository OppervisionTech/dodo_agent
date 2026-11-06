# VALIDATION-20261028 — restore the supported agent/SDK installation contract

Track: Security-Critical. User authorized implementing audited corrections and opening PRs on 2026-10-28. Source: Dodo onboarding/Joka validation and code-audit/agent-sdk.md; no external tracker writes. Branch: fix/dodo-validation-20261028. Base uses the active integration branch because main lacks the shipped implementation.

## Story / decisions
As an SRE I can install a versioned agent in the correct environment and send native SDK or OTLP telemetry through that agent, with durable identity and honest delivery acknowledgement. Keep canonical dodo.proto.v1 SubmitBatch and OTLP on the local loopback listener; HTTP /v1/batch uses protobuf. The agent discards SDK-supplied identity and upstream credentials. No invented release version, public endpoint or new remote plaintext mode.

## Acceptance criteria
- Given a native SDK batch, when submitted to the real local receiver, then canonical paths/payloads are accepted and identity comes from the agent.
- Given malformed, oversized, unsupported or saturated input, then rejection is visible and not counted as delivered; no retries duplicate a partially accepted batch.
- Given a config/installer command, then unsupported flags and invalid config fail before install, endpoints are explicit, artifacts/checksums agree, certificates and identity persist in writable protected state.
- Given an unavailable receiver, shutdown is bounded and statistics distinguish sent and rejected data.

## STRIDE / security acceptance criteria
| Threat | Mitigation / test |
|---|---|
| Spoofing / cross-tenant identity | Agent only accepts local traffic; ignores envelope identity and emits runtime identity. |
| Tampering / distribution | Versioned assets, required validated SHA256, fail on invalid args or invalid YAML. |
| Repudiation / silent drops | Structured accepted/rejected counts; deterministic regression tests. |
| Disclosure / credentials | TLS required beyond loopback, no credential logging, restrictive state/key permissions. |
| Denial of service | Request/body/batch limits, bounded queue/deadlines/shutdown. |
| Elevation | Read-only config and protected writable state; retain local-only listeners. |

## Files / ordered tasks
Planned files: crates/agent-config, crates/agent-collectors/src/otel.rs, crates/agent-collectors/Cargo.toml, crates/agent-transport/src/enrollment.rs, crates/agent-transport/src/proto/mod.rs, crates/agent-transport/src/lib.rs, crates/agent-transport/src/buffer.rs, crates/agent-transport/src/grpc_client.rs, crates/agent-transport/Cargo.toml, Cargo.toml, src/main.rs, get.sh, scripts/install.sh, systemd/aegis-agent.service, config/agent.yaml, Dockerfile, .github/workflows/release.yml, tests, Cargo.lock; this story and integration fixtures/documentation. 1) regression tests, 2) contract implementation, 3) install/config hardening, 4) real receiver smoke, 5) adversarial review and validation record.

## Review / known rollout requirements
Review wire namespace, full/partial rejection accounting, untrusted identity, network trust boundary, archive integrity and Unix permissions. Publish agent artifacts before enabling portal manifest. Linux VM systemd, multiarch Docker and backend-to-storage validation remain explicit release checks when not executable locally.

## Implementation validation
- Canonical native receiver and OTLP share bounded, atomic queue admission. Native metadata cannot override agent identity or emit privileged signals.
- Real SDK smoke exposed and fixed grpc-status placement (now HTTP2 trailers) and incorrect Rust/Go compression enum values (NONE=1, not0).
- Full portable workspace suite passed119tests; final targeted collector/config/transport suite passed73tests, including keyreuse/refreshproof and permissions. Installer contract and integrity fixtures passed. Python/Go gRPC+HTTP realclient smoke through actual agent forwarding passed.
- Linux systemd VM, multiarch image builds, anonymous release assets and backend storage are release checks, not claimed executed locally. No artifact has been published.

## Final review correction — durable offline replay
Replaced destructive read-before-ACK with peek/ack receipts; new writes use unique atomic records and legacy appended records preserve the unconsumed suffix. Periodic replay handles recovery without restart. Invalid/corrupt records are retained. Tests cover same-timestamp records, crash/reopen before ACK, partial legacy ACK and oversize/truncated data. Warm restarts refresh proof-bound JWT before opening upstream transport; rejected upstream counts are recorded separately.

Final replay verification: six agent-transport tests passed (three replay/corruption regressions, canonical compression, host serialization and P256 proof); final Clippy for config/transport/collectors all targets passed without warnings. Extended real-client smoke passed outage recovery both without restart and after process restart while preserving agent_id and persisted records. In-memory data at abrupt process death is not covered by the durable replay contract.
