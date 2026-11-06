# Validation runtime contracts — CI evidence

Track: Security-Critical. The real Linux coverage run executed 155 passing tests but measured 40.20%, below the existing 80% gate. Keep that gate and all authored sources in scope. Add deterministic contracts for the real network, startup, offline replay and command paths; fixtures use loopback and owned temporary files only.

## Acceptance / security criteria

- An actual gRPC UNAVAILABLE response retries within its configured bound; authentication failures and an explicit nonretryable acknowledgement never repeat accepted data. Keep enum status identity rather than comparing its human display text.
- Enrollment followed by a warm restart reuses the same protected private key, refreshes the token before telemetry, and retains previous credentials on malformed/rejected HTTP responses. Redirects remain disabled.
- A real child agent starts against a local fixture, forwards an identified heartbeat, retains its installation ID on restart, and exits cleanly after SIGTERM. Test only the owned child, never the test runner or host services.
- Command contracts execute a per-instance fake kubectl path, never modify PATH or contact a cluster. Timeout must stop the owned process and return an error; temporary manifests are private and removed after use.

## STRIDE

Spoofing: assert enrolled identity and both auth headers on actual requests. Tampering/repudiation: check acknowledgement totals and never replay an explicitly acknowledged subset. Disclosure: synthetic credentials only, certificate/key and manifest permissions checked, no payload secrets logged. Denial of service: bounded subprocess/network waits and cancellation, deterministic fake clock for backoff. Elevation: fake command executable and temporary fixture roots; no real cluster commands or host mutations in tests.

## Tasks / evidence

Transport protocol and retry tests; HTTP enrollment/renewal failure tests; executable startup and graceful shutdown smoke; command arguments/timeout/tempfile contracts; keep full instrumented coverage including child execution. Linux platform fixtures are a separately owned story. Publish a new PR HEAD only after the coordinated local checks finish; preserve all current CI jobs meanwhile.

## PR review follow-up authorized on 2026-10-29

The user approved correcting Agent PR7 after the reviewed findings. Preserve the existing Linux fixtures and runtime contract work. Planned additional files are Cargo.toml, Cargo.lock and crates/agent-collectors/src/certs.rs; CI coverage configuration and existing runtime sources remain in the reviewed scope above.

Certificate acceptance criteria: synthetic PEM and DER certificates yield the expected subject/SAN, exact SHA256 fingerprint and expiration metric; expired certificates preserve the existing zero-day clamp; empty/corrupt/unreadable owned fixture sources do not abort valid sources; no real system certificate paths or network are touched.

Dependency security acceptance criteria: resolve the seven advisories on the reviewed lock by upgrading affected dependency constraints and lock versions, or remove a provably unused dependency while preserving the currently uncompressed wire contract. Re-run the audit against the new lock, preserve Rust compatibility or explicitly resolve an unavoidable supported-toolchain change, and check the Linux/Windows/lite variants. No ignored advisory or lower coverage gate is introduced.

Coverage acceptance: retain all authored production sources and the 80 percent threshold; use one documented Linux coverage engine and instrument owned child agent execution. Record engine, numerator/denominator and commit so local and CI results can be compared.

Shutdown review acceptance: when transport observes cancellation before the batcher finishes its final flush, it must wait for the batch sender to close and process every late batch. A regression uses the real batcher with separately controlled cancellation delivery to reproduce this scheduling order, verifies successful delivery and durable buffering on upstream failure, and releases all owned senders. The main process retains its existing ten-second overall shutdown deadline; producers that do not stop cannot cause an unbounded process shutdown.

Command argument review acceptance: validate namespace, resource and container names and resource-type tokens before spawning kubectl. A single-resource request must reject flag-shaped values such as `--all` and `--raw`, whitespace and shell metacharacters in identity fields. Keep DNS-compatible resource names, qualified Kubernetes types, an optional namespace for DescribeResource, and an optional container for kubectl's default-container selection. Exec's command array remains literal arguments after `--`, including URLs and options. Negative regressions use a per-instance fake executable with an invocation marker and prove that every affected payload is rejected before any subprocess starts.

DescribeResource compatibility: the AI Core's pod-enumeration payload intentionally has an empty name; omit that argument rather than rejecting the read-only request. Read-only resource names also support path-safe RBAC names such as `system:discovery`. Continue rejecting option-shaped names, control characters, path separators, percent escapes and dot-only path segments. Mutating commands still require explicit DNS-compatible resource names; the Describe exceptions must not apply to them.

Follow-up outside this bounded correction: command execution still needs an aggregate concurrency budget, a maximum accepted execution deadline and bounded stdout/stderr capture. Track those denial-of-service controls separately; this correction does not change execution policy, command authorization or process architecture.

Dependency decision: zstd was linked from agent-core but no Rust source calls that codec; remove its unused workspace/core dependency rather than add a new compression behavior. The canonical transport remains Compression::None. Retain other dependencies unless implicated by a measured advisory. Certificate test generation uses the existing rcgen workspace dependency as dev-only.

Coverage engine decision: pin Tarpaulin 0.37.5 and explicitly select LLVM in CI and CD coverage with llvm-tools-preview. The local Linux ARM64 environment cannot use x86_64-only ptrace; selecting the same supported engine also avoids ptrace signal interference in the SIGTERM child lifecycle contract. Keep workspace, Linux features, production source scope and the 80 percent CI gate unchanged. Preserve child profiles and record toolchain/tool versions with each result. Source: https://github.com/xd009642/tarpaulin#nuances-with-llvm-coverage .


### Certificate contract results on 2026-10-29

Added four certificate contracts in `crates/agent-collectors/src/certs.rs` and strengthened the existing defaults contract. All certificate source reads use an in-memory Platform fixture; no real certificate paths, private-key files, network or subprocesses are accessed. Public certificate fixtures are generated with the existing rcgen dependency and retain one exact PEM/DER pair. Contracts verify PEM bundles, raw DER parsing, exact SHA256 identity, DNS/IP SAN display, issuer/subject/serial/CA metadata, expiry inventory and gauge agreement, the existing zero-day clamp, and continuation after inaccessible, empty or corrupt sources.

Scope limitation: the collector's Platform interface reads strings, so these tests certify raw DER at the parser boundary and full collection through PEM; they do not claim binary DER file ingestion is supported or validated. IP SANs retain the existing x509-parser display encoding (`IPAddress(7f:00:00:01)`), without changing production output.

Focused validation on macOS with the revised locked dependencies: `cargo test --locked --offline -p agent-collectors --lib certs::tests -- --test-threads=1` passed 8/8 (4 existing plus 4 new), using the shared Mac cargo cache/target. `rustfmt --edition 2021 --check crates/agent-collectors/src/certs.rs` and scoped `git diff --check` passed. Full Linux workspace coverage and final-head CI remain the coordinated release gates; no coverage threshold or source exclusion changed here.

Linux variant lint acceptance: use the existing generic filesystem_count conversion for statvfs block/inode counters, whose libc aliases vary between 32-bit and 64-bit targets. Preserve disk metrics and saturation semantics while removing same-type casts flagged by Clippy; do not suppress the lint. Existing synthetic filesystem contracts and final Linux coverage exercise the path.

Apply the same statvfs widening conversion in the self-contained lite implementation (crates/agent-platform/src/lite/mod.rs). Both variants must pass Clippy with -D warnings; no lint allow or threshold change.

## Final coordinated verification on 2026-10-29

Linux aarch64 container, Rust1.94.1, Tarpaulin0.37.5, LLVM, workspace/featureslinux and original source exclusions: 202 tests passed, 0 ignored, zero failures; 81.71 percent (3762/4604 lines), above the existing80 percent gate. Compilation reuse used --skip-clean locally; no instrumentation/source/threshold was removed. The isolated container had no external network during execution. This number is a new LLVM baseline and must not be described as numerically equivalent to the old ptrace40.20 measurement.

Clippy passed for linux, windows and lite variants with -Dwarnings. cargo-audit0.22.2 with the official database updated2026-10-29 reported zero blocking vulnerabilities, no ignored advisories; existing informational warnings remain separately visible. Certificate8/8 and command7/7 focused contracts passed. Installer, release/staging bundle, coverage-parser contracts, formatting, actionlint and diff checks passed.
