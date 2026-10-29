# Linux platform: fixture coverage and parser regressions

Related work: VALIDATION-20261028 and agent PR7. Track: existing security-critical validation remediation; user authorized corrections, CI and coordinated staging merge. No live host, credential or patient data is used.

The real Linux Tarpaulin run measured 0/676 platform lines and 40.2% workspace coverage against the unchanged 80% gate. Tests must exercise real parsing and failure paths rather than exclude authored code. Linux source paths and external command locations will be private per-instance dependencies, defaulting to the original host paths/PATH; fixtures will never replace host files, modify process-wide PATH, query actual cloud metadata or run host systemctl.

Acceptance: validate procfs counters/units, physical cores, disk filtering, IPv4/IPv6 socket addresses and ownership, truncated/exited processes, interface addresses, user groups, cgroup limits, host identity and cloud/package/service fallbacks against independent fixtures. Verify IO/parse failures and stable identity persistence. Existing root path defaults and the public Platform trait remains compatible.

Regression findings to test and fix: proc TCP6 consists of four little-endian 32-bit words, while the current decoder discards the final half; malformed process stat may cause an out-of-bounds slice; Azure IMDS JSON with ordinary whitespace must parse like compact JSON; a regular filename containing socket:[inode] must not impersonate a socket owner. Use standard IP/JSON parsing and defensive slices. No collection permissions or public listeners are added.

Files: crates/agent-platform/src/{linux/mod.rs,linux/tests.rs,common.rs}, crates/agent-platform/Cargo.toml. Threats: fixture isolation prevents host mutation/metadata access; untrusted proc contents cannot panic on invalid UTF-8 boundaries/truncation; runtime file/command defaults remain unchanged. Scope and80% gate are preserved.

Validation: fixture tests, feature-specific cargo test/Clippy/fmt; final remote workspace CI and Tarpaulin remain required. Reviewer: primary agent plus independent agent review of final diff before publishing.

Additional restart regression: the fallback host identity used /var/lib/aegis-agent, outside the installer/systemd writable directory and Docker volume /var/lib/aegis. Align new writes to /var/lib/aegis/host-id; preserve/migrate an existing legacy id; fail startup on persistence errors instead of returning an unpersisted random id. Host-id is distinct from agent-id/key. The common module is public: resolve_machine_id now returns PlatformResult<String> instead of String; its two workspace Linux/lite callers are updated. Platform trait signatures remain unchanged. Files include lite/mod.rs. Fixture checks migration, restart,0600 and denied/empty state. Never overwrite an existing identity during concurrent first starts.

Peer review required missing state to remain distinct from unreadable/corrupt legacy state; only NotFound permits generation. Directory/invalidUTF8/empty legacy fixtures must fail without creating a new ID. The concurrent fixture proves that successful starts converge without overwrites; a racer may fail safely while the winner initializes the file.
