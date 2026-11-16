# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0](https://github.com/OppervisionTech/dodo_agent/compare/v0.3.5...v0.4.0) (2026-11-16)


### Features

* add plaintext gRPC mode for local development ([d28b674](https://github.com/OppervisionTech/dodo_agent/commit/d28b674acd5f9e47e96c209f71f75031c711abbe))
* **agent:** --version/--help flags and /healthz, /readyz probe server ([e5bf654](https://github.com/OppervisionTech/dodo_agent/commit/e5bf654d46cb89641aed7eaf396115a062de2282))
* **agent:** add get.sh install script and update Cargo dependencies ([730f5de](https://github.com/OppervisionTech/dodo_agent/commit/730f5de80d9c993756b6953a0fa6ec426c33983b))
* **agent:** working enrollment, --version, health probes, Windows build, k8s via ghcr ([12deefa](https://github.com/OppervisionTech/dodo_agent/commit/12deefa9f22dc82441fd7b88caf98e67e22f51ef))
* **collectors:** logs paths accept service=path to set the service id ([24e8491](https://github.com/OppervisionTech/dodo_agent/commit/24e849150ec31ed0dcc1419df976d4bc376cf0f5))
* **command:** add bidirectional command channel crate ([a6b3d5d](https://github.com/OppervisionTech/dodo_agent/commit/a6b3d5d2ed3caa7aaefaef68596f8dd3ee87780c))
* **HU012-HU035:** implement complete dodo_agent MVP ([ae6150e](https://github.com/OppervisionTech/dodo_agent/commit/ae6150eb76249be67044d1c31b6946001ac25f40))
* **HU035:** add packaging, cross-compilation, Docker, and release workflow ([ee21b4f](https://github.com/OppervisionTech/dodo_agent/commit/ee21b4f4e1e4884d0ead6f4d5a151fd3e0c79fe0))
* **HU260-263:** implement OTEL passthrough, Docker, PostgreSQL, MongoDB, Redis collectors ([ecbd3b3](https://github.com/OppervisionTech/dodo_agent/commit/ecbd3b3e40b361bb83926722607183025c4265be))
* **HU278:** real incident flow, Aegis FinOps agent and GCP integration ([aab74fe](https://github.com/OppervisionTech/dodo_agent/commit/aab74fede764a9eae4d2930ad6e4d342f40d4faf))
* integrate signed agent identity proof (Arthur's [#7](https://github.com/OppervisionTech/dodo_agent/issues/7)) into develop, v0.3.0 ([7864fbb](https://github.com/OppervisionTech/dodo_agent/commit/7864fbbbf1d6ad278480a6d1484e58058b24b07e))
* **platform:** DODO_HOST_ID fixa a identidade do host ([35c2b35](https://github.com/OppervisionTech/dodo_agent/commit/35c2b3504c8aa9b403e23fb29ac28b3f3b8295f6))
* **platform:** pin the host identity with DODO_HOST_ID ([6997d86](https://github.com/OppervisionTech/dodo_agent/commit/6997d86073388ca14cc4ff584ebd76041fcc0993))


### Bug Fixes

* **agent:** default to the live staging gRPC and enrollment endpoints ([03141d6](https://github.com/OppervisionTech/dodo_agent/commit/03141d626858ac477d6fbc215925003a3eaf6dc3))
* **agent:** update helpers and dependency lock ([15d1ae8](https://github.com/OppervisionTech/dodo_agent/commit/15d1ae8e51ab5df6ae15e2b74c0206447f6f3596))
* **batcher:** drain queued envelopes on shutdown ([7558716](https://github.com/OppervisionTech/dodo_agent/commit/7558716e9e734cab609e65e480498ba431e55b5b))
* **buffer:** re-check space after eviction and return error when full ([449a914](https://github.com/OppervisionTech/dodo_agent/commit/449a9140feae050e0ab6ca6e08934d58e9e36386))
* **cd:** add container logs to debug step, fix dry-run values ([791d048](https://github.com/OppervisionTech/dodo_agent/commit/791d0482343371e19b00c19d2623a970b6413e1d))
* **cd:** add GHCR imagePullSecret and pod debug on failure ([443d6a7](https://github.com/OppervisionTech/dodo_agent/commit/443d6a79c2305974142859a432720c8442b2a49b))
* **cd:** build only linux/amd64 for DOKS deploy ([668870d](https://github.com/OppervisionTech/dodo_agent/commit/668870de5243f1a7d9ae37b5579708a4ba29a6e9))
* **cd:** patch ServiceAccount with imagePullSecret after helm install ([8643d91](https://github.com/OppervisionTech/dodo_agent/commit/8643d912a73ff72a40f3ab74bf269ace881355c3))
* **cd:** set namespace pod-security to privileged before helm deploy ([094fd3d](https://github.com/OppervisionTech/dodo_agent/commit/094fd3de25a414f4efe3afcf42bd628e5a0a1313))
* **ci:** make Docker Hub push conditional on secrets being configured ([db5312e](https://github.com/OppervisionTech/dodo_agent/commit/db5312ee629a9a66fda34e5430163880c0a8005e))
* **ci:** resolve all clippy warnings and fix tests using protobuf payloads ([ca2cffb](https://github.com/OppervisionTech/dodo_agent/commit/ca2cffb807d1e4b60ccf7c8a00b69eb82c726c78))
* **ci:** resolve clippy, test and security audit failures ([594d6e4](https://github.com/OppervisionTech/dodo_agent/commit/594d6e4d90b3017b2b0d225dde811c4da42deaf6))
* **ci:** resolve remaining clippy warnings ([a64a2a6](https://github.com/OppervisionTech/dodo_agent/commit/a64a2a6a8ebff873c78def2a6d46c893c83bc2d7))
* **ci:** silence dead_code/unused_imports in otel.rs for non-otel builds ([1334aed](https://github.com/OppervisionTech/dodo_agent/commit/1334aede90c407636e3f5fb0fd9a0915b7c68798))
* **collectors:** docker timeout, DB metrics/logs under their service ([#5](https://github.com/OppervisionTech/dodo_agent/issues/5)) ([978e644](https://github.com/OppervisionTech/dodo_agent/commit/978e644343f1e64085da6f03c8bf0dfb2c432c0e))
* **collectors:** fetch docker container stats concurrently ([fcde2a1](https://github.com/OppervisionTech/dodo_agent/commit/fcde2a1951ba6a81049dfc7bcd140efefbc8e948))
* **collectors:** tag postgres/redis/mongodb metrics with service label ([045eab2](https://github.com/OppervisionTech/dodo_agent/commit/045eab2860d2b4399be44543bf3671f10b3a7d40))
* **collectors:** update mongodb collector ([06b598a](https://github.com/OppervisionTech/dodo_agent/commit/06b598aa6171c5bea28c5405e0626f35e578ab98))
* **deps:** bump rustls-webpki, webpki-roots and ctutils ([730fd65](https://github.com/OppervisionTech/dodo_agent/commit/730fd65384c3107251395a91288320e6040cce73))
* **deps:** resolve advisories do cargo audit ([#33](https://github.com/OppervisionTech/dodo_agent/issues/33)) ([a6ee89e](https://github.com/OppervisionTech/dodo_agent/commit/a6ee89ef23aee6ab2d3ce2397289c049cc33bbb2))
* **docker:** bound Docker API reads (size and time) ([764c4ce](https://github.com/OppervisionTech/dodo_agent/commit/764c4ce7f571a66706dba3a425a2f5ac18435a26))
* **get.sh:** drop dead aegisops.io references from help output ([4a6c00b](https://github.com/OppervisionTech/dodo_agent/commit/4a6c00b5282a545e48025a007558f2fd4d17a54f))
* **get.sh:** drop dead aegisops.io references from help output ([9629350](https://github.com/OppervisionTech/dodo_agent/commit/9629350d6a4b62d118bb2832a911c511641b71df))
* **get.sh:** installer contract tests for the public installer ([a584a26](https://github.com/OppervisionTech/dodo_agent/commit/a584a26bc52503cfebc29b2fe2e978b0c9878567))
* **get.sh:** k8s mode installs only from the ghcr OCI chart ([adddfc2](https://github.com/OppervisionTech/dodo_agent/commit/adddfc2a0bf9538808ff3eb0e93fc1ba70ae0b73))
* **get.sh:** make mTLS certificate enrollment actually plug-and-play ([2925ebe](https://github.com/OppervisionTech/dodo_agent/commit/2925ebe36ce964649083629a5f6b4216f5ed9a6f))
* **installer:** public releases repo + get.sh fixes ([#8](https://github.com/OppervisionTech/dodo_agent/issues/8)) ([5ab87a2](https://github.com/OppervisionTech/dodo_agent/commit/5ab87a2df9acffa4ac9880ae8c85d321d4315514))
* **installer:** restart on re-install; fresh identity when the API key changes ([ac59655](https://github.com/OppervisionTech/dodo_agent/commit/ac596552f4fa1f3433f10e750b2b0542c406bffa))
* **k8s:** logs de pod usam container como service e host usa NODE_NAME ([#32](https://github.com/OppervisionTech/dodo_agent/issues/32)) ([862c56f](https://github.com/OppervisionTech/dodo_agent/commit/862c56fd4f74c948f3b6f7f120c23113d71e0cbc))
* make installation and SDK ingestion reliable ([#7](https://github.com/OppervisionTech/dodo_agent/issues/7)) ([4e03613](https://github.com/OppervisionTech/dodo_agent/commit/4e036132204dded052eca9b169fc981f8c633cc4))
* **release:** amd64-only image, publish binaries without waiting on it ([ca32bc1](https://github.com/OppervisionTech/dodo_agent/commit/ca32bc1dff78c062a4682f0dd61c40f821bd53a1))
* **release:** build non-linux variants with --no-default-features ([#10](https://github.com/OppervisionTech/dodo_agent/issues/10)) ([f602c1a](https://github.com/OppervisionTech/dodo_agent/commit/f602c1ab5066cc6e6c6b1e7c7520bb6c53ba788f))
* **release:** package the single aegis-agent binary per variant ([8ccdcdf](https://github.com/OppervisionTech/dodo_agent/commit/8ccdcdf4bb4be63dc6d5322fbb7550a00cfb9ff5))
* resolve all compilation errors for local dev testing ([1b81a5e](https://github.com/OppervisionTech/dodo_agent/commit/1b81a5e40b841d669565308b9063a0efc40b5508))
* **transport:** disk buffering no longer freezes the agent ([#38](https://github.com/OppervisionTech/dodo_agent/issues/38)) ([ae5b06e](https://github.com/OppervisionTech/dodo_agent/commit/ae5b06eba53e0822bf32b6737d587118c56a4aa3))
* **transport:** drain all batches on shutdown and buffer failed sends to disk ([ae072d3](https://github.com/OppervisionTech/dodo_agent/commit/ae072d38a8a24b3b400d19b4cb425f6849828b90))
* **transport:** native TLS roots, mTLS+JWT enrollment, bounded connect timeouts ([#1](https://github.com/OppervisionTech/dodo_agent/issues/1)) ([1fb3195](https://github.com/OppervisionTech/dodo_agent/commit/1fb31959295c2ed23b377bc5c5cbb029b3c80425))
* **transport:** retry tonic timeouts; smaller batches, longer deadline ([4e79ad4](https://github.com/OppervisionTech/dodo_agent/commit/4e79ad462f1c8a02416567f24757f6636856fd13))
* **transport:** retry tonic timeouts; smaller batches, longer deadline ([3753472](https://github.com/OppervisionTech/dodo_agent/commit/3753472b27940d7bd287146610b6f526f91d9566))
* **transport:** send batches in size-bounded chunks ([#37](https://github.com/OppervisionTech/dodo_agent/issues/37)) ([a5b461a](https://github.com/OppervisionTech/dodo_agent/commit/a5b461a8e35f084df460e8f9c64e031325334661))
* **windows:** connect to Docker via named pipe; re-enable windows release ([20d54ef](https://github.com/OppervisionTech/dodo_agent/commit/20d54ef3aba1ed21412c426e697a7dae0aea6ded))

## [Unreleased]

## [0.3.5] - 2026-11-16

### Fixed
- Batches are sent in chunks under 3 MB, so the ingestor no longer rejects large log batches (#37).
- A failed batch no longer freezes the agent: disk buffering runs off the async workers, writes one file per priority (max ~1 MB) with one fsync, and keeps its size cached (#38).
- Disk buffer eviction never deletes higher-priority data, no longer spins forever when space is short, and leftover temporary files are removed (#38).

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
