#!/usr/bin/env bash
#
# DoDo AegisOps Agent — Installation Script
# Usage: sudo ./install.sh [--variant linux|lite]
#
set -euo pipefail

VARIANT="${1:-linux}"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/aegis"
DATA_DIR="/var/lib/aegis"
BUFFER_DIR="${DATA_DIR}/buffer"
CERTS_DIR="${CONFIG_DIR}/certs"
LOG_DIR="/var/log/aegis"
SERVICE_USER="aegis-agent"
BINARY_NAME="aegis-agent"

echo "=== DoDo AegisOps Agent Installer ==="
echo "Variant: ${VARIANT}"
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

# Copy binary
if [[ -f "./${BINARY_NAME}" ]]; then
    echo "Installing binary..."
    cp "./${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
    chmod 755 "${INSTALL_DIR}/${BINARY_NAME}"
elif [[ -f "target/release/${BINARY_NAME}" ]]; then
    echo "Installing binary from build..."
    cp "target/release/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
    chmod 755 "${INSTALL_DIR}/${BINARY_NAME}"
else
    echo "ERROR: Binary not found. Build first with: make build-${VARIANT}"
    exit 1
fi

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
  address: "kong.aegisops.io:443"
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
