# DoDo AegisOps Agent — Multi-Stage Docker Build
#
# Build:
#   docker build -t aegis-agent:latest .
#   docker build --build-arg VARIANT=lite -t aegis-agent-lite:latest .
#
# Run:
#   docker run -d --name aegis-agent \
#     -v /etc/aegis:/etc/aegis:ro \
#     -v /var/lib/aegis:/var/lib/aegis \
#     -v /proc:/host/proc:ro \
#     -v /sys:/host/sys:ro \
#     aegis-agent:latest

# ---------- Stage 1: Build ----------
FROM rust:latest AS builder

ARG VARIANT=linux
ARG TARGETARCH=amd64

# Install musl toolchain for static linking
RUN apt-get update && apt-get install -y --no-install-recommends \
    musl-tools \
    && rm -rf /var/lib/apt/lists/*

# Add musl target
RUN case "${TARGETARCH}" in \
        amd64) rustup target add x86_64-unknown-linux-musl ;; \
        arm64) rustup target add aarch64-unknown-linux-musl ;; \
    esac

WORKDIR /build

# Cache dependencies — copy manifests first
COPY Cargo.toml Cargo.lock ./
COPY crates/agent-core/Cargo.toml crates/agent-core/
COPY crates/agent-collectors/Cargo.toml crates/agent-collectors/
COPY crates/agent-transport/Cargo.toml crates/agent-transport/
COPY crates/agent-config/Cargo.toml crates/agent-config/
COPY crates/agent-command/Cargo.toml crates/agent-command/
COPY crates/agent-ebpf/Cargo.toml crates/agent-ebpf/
COPY crates/agent-platform/Cargo.toml crates/agent-platform/

# Create stub lib.rs files for dependency caching
RUN for crate in agent-core agent-collectors agent-transport agent-command agent-config agent-ebpf agent-platform; do \
        mkdir -p "crates/${crate}/src" && echo "" > "crates/${crate}/src/lib.rs"; \
    done && \
    mkdir -p src && echo "fn main() {}" > src/main.rs

# Build dependencies only (cached layer)
RUN case "${TARGETARCH}" in \
        amd64) TARGET=x86_64-unknown-linux-musl ;; \
        arm64) TARGET=aarch64-unknown-linux-musl ;; \
    esac && \
    cargo build --release --no-default-features --features "${VARIANT}" --target "${TARGET}" 2>/dev/null || true

# Copy actual source
COPY crates/ crates/
COPY src/ src/

# Touch source files to invalidate cache for actual build
RUN find crates/ src/ -name "*.rs" -exec touch {} +

# Final build
RUN case "${TARGETARCH}" in \
        amd64) TARGET=x86_64-unknown-linux-musl ;; \
        arm64) TARGET=aarch64-unknown-linux-musl ;; \
    esac && \
    cargo build --release --no-default-features --features "${VARIANT}" --target "${TARGET}" && \
    cp "target/${TARGET}/release/aegis-agent" /aegis-agent

# ---------- Stage 2: Runtime ----------
FROM gcr.io/distroless/static-debian12

LABEL org.opencontainers.image.title="DoDo AegisOps Agent"
LABEL org.opencontainers.image.description="Telemetry collection agent for DoDo AegisOps AI"
LABEL org.opencontainers.image.vendor="Oppervision"
LABEL org.opencontainers.image.source="https://github.com/OppervisionTech/dodo_agent"

COPY --from=builder /aegis-agent /usr/local/bin/aegis-agent
COPY config/agent.yaml /etc/aegis/agent.yaml

# Config and data directories are expected to be mounted
# /etc/aegis       — configuration (read-only)
# /var/lib/aegis   — agent data and buffer (read-write)
# /host/proc       — host proc filesystem (read-only)
# /host/sys        — host sys filesystem (read-only)

ENV AEGIS_CONFIG=/etc/aegis/agent.yaml
ENV RUST_LOG=info

ENTRYPOINT ["/usr/local/bin/aegis-agent"]
