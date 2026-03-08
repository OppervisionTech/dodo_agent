# dodo_agent

Telemetry collection agent for the **DoDo AegisOps AI** observability platform by [Oppervision](https://oppervision.com).

A single Rust binary that runs on every monitored host, collects all telemetry signals (metrics, logs, traces, security events, inventory), packages them as `AgentEnvelope` (Protobuf), and ships them via gRPC+mTLS to the AegisOps ingestion pipeline.

## 3 Variants (same codebase, feature flags)

| Variant | Target | eBPF | Compression | RAM | CPU idle |
|---------|--------|------|-------------|-----|----------|
| `aegis-agent` | Linux (VM, Bare Metal, K8s) | Yes (kernel >= 5.8) | zstd | < 50 MB | < 0.8% |
| `aegis-agent-windows` | Windows Server/Desktop | ETW replaces eBPF | zstd | < 80 MB | < 1% |
| `aegis-agent-lite` | IoT/Edge (ARM, MIPS, RISC-V) | No | lz4 | < 20 MB | < 0.5% |

## 13 Collectors

| Collector | Interval | Source |
|-----------|----------|--------|
| CPU & Compute | 5 s | /proc/stat, cgroups |
| Memory & Swap | 5 s | /proc/meminfo, cgroups |
| Disk & I/O | 10 s | /proc/diskstats, SMART |
| Network & Traffic | 5 s | /proc/net, eBPF socket/tc |
| Processes & Runtime | 10 s | /proc, eBPF execve |
| Security & Ports | 15 s | inotify, eBPF, auditd |
| TLS Certificates | 1 h | /etc/ssl, K8s secrets |
| Logs & Journaling | streaming | journald, syslog, app logs |
| OTEL Passthrough | continuous | localhost:4317/4318 |
| Kubernetes & Containers | 15 s | K8s API, cAdvisor |
| Inventory & Identity | boot + 1 h | /etc, IMDSv2, WMI |
| Self-metrics | 30 s | internal counters |
| Heartbeat | 30 s | agent state |

## Architecture

```
dodo_agent/
├── Cargo.toml                     # Workspace + feature flags
├── src/main.rs                    # Binary entry point
├── crates/
│   ├── agent-core/                # Scheduler, batcher, collector trait, redaction, signals
│   ├── agent-collectors/          # All 13 collectors as modules
│   ├── agent-transport/           # gRPC client, mTLS, disk buffer, retry
│   ├── agent-config/              # YAML config loader, hot reload watcher, merger
│   ├── agent-ebpf/                # eBPF manager (feature-gated, Linux only)
│   └── agent-platform/            # OS abstraction layer (Linux/Windows/Lite)
├── config/                        # Default YAML config
├── scripts/                       # Install script
├── systemd/                       # systemd unit file
└── tests/                         # Integration tests
```

## Building

```bash
# Linux variant (default)
cargo build --release --features linux

# Windows variant
cargo build --release --no-default-features --features windows

# Lite/IoT variant
cargo build --release --no-default-features --features lite
```

## Testing

```bash
# Run all tests
cargo test --workspace --no-default-features

# Run tests for a specific crate
cargo test -p agent-core
cargo test -p agent-collectors
```

## Linting

```bash
cargo fmt --all --check
cargo clippy --no-default-features
cargo clippy --features linux
```

## Configuration

The agent reads a YAML config file (default: `/etc/aegis/agent.yaml`). See [`config/agent.yaml`](config/agent.yaml) for the default configuration.

Key behaviors:
- **Batching**: flush every 5 s or 500 envelopes (whichever comes first)
- **Disk buffer**: 512 MB local buffer when ingestor is unreachable, priority-ordered drain (security > heartbeat > metrics > logs)
- **Hot reload**: config changes detected via SHA-256 hash, applied without restart
- **Secret redaction**: passwords, tokens, API keys, AWS credentials, Bearer tokens, SSH keys are redacted before leaving the host
- **Graceful shutdown**: SIGTERM/SIGINT trigger orderly shutdown with 10 s timeout

## License

Proprietary - Oppervision Soluções de Monitoramento e Automação.
