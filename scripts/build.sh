#!/usr/bin/env bash
#
# DoDo AegisOps Agent — Cross-Compilation Build Script
# Builds static Linux binaries for amd64 and arm64 using musl.
#
# Usage:
#   ./scripts/build.sh                    # Build all targets
#   ./scripts/build.sh linux-amd64        # Build only linux amd64
#   ./scripts/build.sh linux-arm64        # Build only linux arm64
#   ./scripts/build.sh lite-arm64         # Build lite variant for arm64
#
# Requirements:
#   - Rust toolchain with musl targets: rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
#   - For arm64 cross-compilation: `cross` (cargo install cross) OR aarch64-linux-musl-gcc
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERSION="${VERSION:-$(grep '^version' "${PROJECT_ROOT}/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/' 2>/dev/null || echo "dev")}"
DIST_DIR="${PROJECT_ROOT}/dist"

# Targets
TARGET_AMD64="x86_64-unknown-linux-musl"
TARGET_ARM64="aarch64-unknown-linux-musl"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

check_prerequisites() {
    command -v cargo >/dev/null 2>&1 || error "cargo not found. Install Rust: https://rustup.rs"

    if [[ "${USE_CROSS:-0}" == "1" ]]; then
        command -v cross >/dev/null 2>&1 || error "cross not found. Install: cargo install cross"
        info "Using 'cross' for cross-compilation"
        BUILD_CMD="cross"
    else
        BUILD_CMD="cargo"
    fi
}

build_target() {
    local feature="$1"
    local target="$2"
    local output_name="$3"
    local arch_label="$4"

    info "Building ${output_name} (${arch_label}, feature=${feature})..."

    # Ensure target is installed (for native cargo builds)
    if [[ "${BUILD_CMD}" == "cargo" ]]; then
        rustup target add "${target}" 2>/dev/null || true
    fi

    ${BUILD_CMD} build \
        --release \
        --features "${feature}" \
        --target "${target}" \
        --manifest-path "${PROJECT_ROOT}/Cargo.toml"

    local src="${PROJECT_ROOT}/target/${target}/release/aegis-agent"
    local dest_dir="${DIST_DIR}/${arch_label}"
    mkdir -p "${dest_dir}"
    cp "${src}" "${dest_dir}/${output_name}"

    # Generate SHA256 checksum
    (cd "${dest_dir}" && sha256sum "${output_name}" > "${output_name}.sha256")

    local size
    size=$(du -h "${dest_dir}/${output_name}" | cut -f1)
    info "  -> ${dest_dir}/${output_name} (${size})"
}

build_linux_amd64() {
    build_target "linux" "${TARGET_AMD64}" "aegis-agent" "linux-amd64"
}

build_linux_arm64() {
    # arm64 typically requires cross or a cross-compiler
    if [[ "${BUILD_CMD}" == "cargo" ]]; then
        warn "arm64 cross-compilation may require USE_CROSS=1 or aarch64-linux-musl-gcc"
    fi
    build_target "linux" "${TARGET_ARM64}" "aegis-agent" "linux-arm64"
}

build_lite_arm64() {
    if [[ "${BUILD_CMD}" == "cargo" ]]; then
        warn "arm64 cross-compilation may require USE_CROSS=1 or aarch64-linux-musl-gcc"
    fi
    build_target "lite" "${TARGET_ARM64}" "aegis-agent-lite" "lite-arm64"
}

build_lite_amd64() {
    build_target "lite" "${TARGET_AMD64}" "aegis-agent-lite" "lite-amd64"
}

create_release_archive() {
    info "Creating release archives..."
    for arch_dir in "${DIST_DIR}"/*/; do
        [[ -d "${arch_dir}" ]] || continue
        local arch_name
        arch_name=$(basename "${arch_dir}")
        local archive="${DIST_DIR}/aegis-agent-${VERSION}-${arch_name}.tar.gz"
        tar -czf "${archive}" -C "${arch_dir}" .
        (cd "${DIST_DIR}" && sha256sum "$(basename "${archive}")" >> "checksums-${VERSION}.sha256")
        info "  -> ${archive}"
    done
}

main() {
    check_prerequisites

    local target="${1:-all}"

    info "=== DoDo AegisOps Agent Build ==="
    info "Version: ${VERSION}"
    info "Output:  ${DIST_DIR}"
    echo ""

    mkdir -p "${DIST_DIR}"

    case "${target}" in
        linux-amd64)
            build_linux_amd64
            ;;
        linux-arm64)
            build_linux_arm64
            ;;
        lite-arm64)
            build_lite_arm64
            ;;
        lite-amd64)
            build_lite_amd64
            ;;
        all)
            build_linux_amd64
            build_linux_arm64
            build_lite_amd64
            build_lite_arm64
            create_release_archive
            ;;
        *)
            error "Unknown target: ${target}. Valid: linux-amd64, linux-arm64, lite-amd64, lite-arm64, all"
            ;;
    esac

    echo ""
    info "=== Build Complete ==="
}

main "$@"
