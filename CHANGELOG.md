# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-03-01

### Added
- 13 collectors: CPU, Memory, Disk, Network, Process, Security, Certificates, Logs, OTEL, SDK, Kubernetes, Inventory, Self-metrics
- Linux standard variant with eBPF support (kernel >= 5.8)
- Linux lite variant for IoT/Edge (< 20MB RAM, lz4 compression)
- Windows variant with ETW (replaces eBPF)
- Static musl binaries for Linux (amd64, arm64)
- gRPC + mTLS transport to Kong/AegisOps backend with zstd compression
- Local disk buffer for resilience (512MB default, priority queue: security > heartbeat > metrics > logs)
- Config hot reload every 60s without restart
- Permanent agent_id (UUID v4) persisted on first boot
- Multi-arch Docker image (linux/amd64, linux/arm64)
- One-liner install script
