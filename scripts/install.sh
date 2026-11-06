#!/usr/bin/env bash
#
# DoDo AegisOps Agent — Installation Script
#
# Local install (from build or extracted archive):
#   sudo ./install.sh [linux|lite]
#
# One-liner install (downloads from GitHub Releases):
#   curl -fsSL https://releases.aegisops.io/install.sh | sudo bash -s -- [--version v0.1.0] [--variant linux|lite]
#
set -euo pipefail

GITHUB_REPO="oppervision/dodo_agent"
VARIANT=""
VERSION="latest"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/aegis"
DATA_DIR="/var/lib/aegis"
BUFFER_DIR="${DATA_DIR}/buffer"
CERTS_DIR="${CONFIG_DIR}/certs"
LOG_DIR="/var/log/aegis"
SERVICE_USER="aegis-agent"
BINARY_NAME="aegis-agent"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)  VERSION="$2"; shift 2 ;;
        --variant)  VARIANT="$2"; shift 2 ;;
        linux|lite) VARIANT="$1"; shift ;;
        *)          echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Detect architecture and set defaults
ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64|amd64)  ARCH_LABEL="amd64" ;;
    aarch64|arm64) ARCH_LABEL="arm64" ;;
    *)             echo "ERROR: Unsupported architecture: ${ARCH}"; exit 1 ;;
esac

if [[ -z "${VARIANT}" ]]; then
    VARIANT="linux"
fi

if [[ "${VARIANT}" == "lite" ]]; then
    BINARY_NAME="aegis-agent-lite"
fi

echo "=== DoDo AegisOps Agent Installer ==="
echo "Variant: ${VARIANT}"
echo "Arch:    ${ARCH_LABEL}"
echo "Version: ${VERSION}"
echo ""

# Check root
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (sudo)"
    exit 1
fi

# Create system user (no login shell, no home)
if ! id "${SERVICE_USER}" &>/dev/null; then
    echo "Creating user ${SERVICE_USER}..."
    useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
fi

# Create directories
echo "Creating directories..."
mkdir -p "${INSTALL_DIR}"
mkdir -p "${CONFIG_DIR}"
mkdir -p "${CERTS_DIR}"
mkdir -p "${DATA_DIR}"
mkdir -p "${BUFFER_DIR}"
mkdir -p "${LOG_DIR}"

# Find or download binary
install_binary() {
    # 1. Check local binary in current directory
    if [[ -f "./${BINARY_NAME}" ]]; then
        echo "Installing binary from current directory..."
        cp "./${BINARY_NAME}" "${INSTALL_DIR}/aegis-agent"
        return 0
    fi

    # 2. Check target/release from build
    if [[ -f "target/release/${BINARY_NAME}" ]]; then
        echo "Installing binary from build output..."
        cp "target/release/${BINARY_NAME}" "${INSTALL_DIR}/aegis-agent"
        return 0
    fi

    # 3. Check dist/ from build.sh
    local dist_variant="${VARIANT}-${ARCH_LABEL}"
    if [[ -f "dist/${dist_variant}/${BINARY_NAME}" ]]; then
        echo "Installing binary from dist/..."
        cp "dist/${dist_variant}/${BINARY_NAME}" "${INSTALL_DIR}/aegis-agent"
        return 0
    fi

    # 4. Download from GitHub Releases
    echo "Downloading from GitHub Releases..."
    command -v curl >/dev/null 2>&1 || { echo "ERROR: curl required for download"; exit 1; }

    local download_url
    local archive_name="aegis-agent-${VARIANT}-${ARCH_LABEL}.tar.gz"
    if [[ "${VERSION}" == "latest" ]]; then
        download_url="https://github.com/${GITHUB_REPO}/releases/latest/download/${archive_name}"
    else
        download_url="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${archive_name}"
    fi

    local tmp_dir
    tmp_dir="$(mktemp -d)"
    trap 'rm -rf "${tmp_dir}"' EXIT

    echo "  URL: ${download_url}"
    curl -fSL "${download_url}" -o "${tmp_dir}/archive.tar.gz"

    # Verify checksum if available
    local checksum_url="${download_url}.sha256"
    if curl -fsSL "${checksum_url}" -o "${tmp_dir}/checksum.sha256" 2>/dev/null; then
        echo "Verifying checksum..."
        (cd "${tmp_dir}" && echo "$(cat checksum.sha256)  archive.tar.gz" | sha256sum -c -)
    fi

    tar -xzf "${tmp_dir}/archive.tar.gz" -C "${tmp_dir}"
    cp "${tmp_dir}/${BINARY_NAME}" "${INSTALL_DIR}/aegis-agent"
    return 0
}

install_binary
chmod 755 "${INSTALL_DIR}/aegis-agent"

# Set capabilities (instead of running as root)
echo "Setting capabilities..."
setcap 'cap_bpf,cap_perfmon,cap_net_raw,cap_dac_read_search=eip' "${INSTALL_DIR}/${BINARY_NAME}" 2>/dev/null || \
    echo "WARNING: Failed to set capabilities. Agent may need to run as root."

# Copy default config
if [[ ! -f "${CONFIG_DIR}/agent.yaml" ]]; then
    echo "Installing default configuration..."
    if [[ -f "config/agent.yaml" ]]; then
        cp "config/agent.yaml" "${CONFIG_DIR}/agent.yaml"
    else
        echo "WARNING: Default config not found, creating minimal config"
        cat > "${CONFIG_DIR}/agent.yaml" << 'YAML'
endpoint:
  address: "grpc.stg.dodo.oppervision.com.br:443"
logging:
  level: "info"
YAML
    fi
fi

# Set ownership
echo "Setting permissions..."
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${DATA_DIR}"
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${LOG_DIR}"
chown -R root:${SERVICE_USER} "${CONFIG_DIR}"
chmod 750 "${CONFIG_DIR}"
chmod 640 "${CONFIG_DIR}/agent.yaml"
chmod 700 "${CERTS_DIR}"

# Install systemd service
if command -v systemctl &>/dev/null; then
    echo "Installing systemd service..."
    if [[ -f "systemd/aegis-agent.service" ]]; then
        cp "systemd/aegis-agent.service" /etc/systemd/system/aegis-agent.service
    fi
    systemctl daemon-reload
    systemctl enable aegis-agent
    echo "Service installed. Start with: systemctl start aegis-agent"
fi

# Generate SHA256 checksum
echo ""
echo "Binary checksum:"
sha256sum "${INSTALL_DIR}/${BINARY_NAME}"

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Next steps:"
echo "  1. Place TLS certificates in ${CERTS_DIR}/"
echo "     - ca.pem (CA certificate)"
echo "     - agent.pem (client certificate)"
echo "     - agent-key.pem (client private key)"
echo "  2. Edit ${CONFIG_DIR}/agent.yaml with your endpoint address"
echo "  3. Start the agent: systemctl start aegis-agent"
echo "  4. Check status: systemctl status aegis-agent"
echo "  5. View logs: journalctl -u aegis-agent -f"
