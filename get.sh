#!/usr/bin/env bash
#
# DoDo AegisOps Agent — Universal Install Script
#
# Usage:
#   curl -fsSL https://get.aegisops.io/agent | bash
#   curl -fsSL https://get.aegisops.io/agent | bash -s -- --mode dev --api-key MY_KEY
#   curl -fsSL https://get.aegisops.io/agent | bash -s -- --mode server --api-key MY_KEY
#   curl -fsSL https://get.aegisops.io/agent | bash -s -- --mode k8s --api-key MY_KEY
#
# All flags can also be set via env vars:
#   DODO_MODE, DODO_API_KEY, DODO_ENDPOINT, DODO_VARIANT, DODO_VERSION,
#   DODO_NAMESPACE, DODO_TLS_SECRET, DODO_NON_INTERACTIVE
#
set -euo pipefail

# ─── Constants ────────────────────────────────────────────────────────────────

readonly SCRIPT_VERSION="0.1.0"
readonly GITHUB_REPO="oppervision/dodo_agent"
readonly GITHUB_RELEASES_BASE="https://github.com/${GITHUB_REPO}/releases"
readonly DOCKER_IMAGE="ghcr.io/oppervisiontech/aegis-agent"
readonly HELM_OCI_CHART="oci://ghcr.io/oppervisiontech/charts/aegis-agent"
readonly HELM_REPO_NAME="aegisops"
readonly HELM_REPO_URL="https://charts.aegisops.io"
readonly HEALTH_PORT="9090"

# Server mode directories
readonly INSTALL_DIR="/usr/local/bin"
readonly CONFIG_DIR="/etc/aegis"
# Certs live under DATA_DIR (not CONFIG_DIR): the systemd unit mounts
# /etc/aegis read-only (ReadOnlyPaths), but the agent process needs to write
# ca.pem/agent.pem/agent-key.pem here itself via mTLS auto-enrollment.
readonly CERTS_DIR="/var/lib/aegis/certs"
readonly DATA_DIR="/var/lib/aegis"
readonly BUFFER_DIR="/var/lib/aegis/buffer"
readonly LOG_DIR="/var/log/aegis"
readonly SERVICE_USER="aegis-agent"

# ─── Colors / Logging ─────────────────────────────────────────────────────────

if [ -t 1 ] && [ -t 2 ]; then
  RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
  BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'
else
  RED=''; YELLOW=''; GREEN=''; BLUE=''; BOLD=''; RESET=''
fi

info()  { printf "${GREEN}[INFO]${RESET}  %s\n" "$*"; }
warn()  { printf "${YELLOW}[WARN]${RESET}  %s\n" "$*" >&2; }
error() { printf "${RED}[ERROR]${RESET} %s\n" "$*" >&2; exit 1; }
step()  { printf "\n${BOLD}${BLUE}==> %s${RESET}\n" "$*"; }
ok()    { printf "${GREEN}[ OK ]${RESET}  %s\n" "$*"; }

# ─── Argument Parsing ─────────────────────────────────────────────────────────

DODO_MODE="${DODO_MODE:-}"
DODO_API_KEY="${DODO_API_KEY:-}"
DODO_ENDPOINT="${DODO_ENDPOINT:-}"
DODO_ENROLLMENT_ENDPOINT="${DODO_ENROLLMENT_ENDPOINT:-}"
DODO_VARIANT="${DODO_VARIANT:-}"
DODO_VERSION="${DODO_VERSION:-latest}"
DODO_NAMESPACE="${DODO_NAMESPACE:-dodo}"
DODO_TLS_SECRET="${DODO_TLS_SECRET:-}"
DODO_NON_INTERACTIVE="${DODO_NON_INTERACTIVE:-false}"

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --mode)                DODO_MODE="$2";                shift 2 ;;
      --api-key)             DODO_API_KEY="$2";              shift 2 ;;
      --endpoint)             DODO_ENDPOINT="$2";             shift 2 ;;
      --enrollment-endpoint) DODO_ENROLLMENT_ENDPOINT="$2";  shift 2 ;;
      --variant)              DODO_VARIANT="$2";              shift 2 ;;
      --version)              DODO_VERSION="$2";              shift 2 ;;
      --namespace)            DODO_NAMESPACE="$2";            shift 2 ;;
      --tls-secret)           DODO_TLS_SECRET="$2";           shift 2 ;;
      --non-interactive)      DODO_NON_INTERACTIVE=true;      shift ;;
      --)                     shift; break ;;
      -*) warn "Unknown option: $1"; shift ;;
    esac
  done
}

# ─── Input Validation ─────────────────────────────────────────────────────────

validate_inputs() {
  if [[ -n "${DODO_MODE}" ]]; then
    case "${DODO_MODE}" in
      server|k8s|dev) ;;
      *) error "Invalid --mode '${DODO_MODE}'. Must be: server | k8s | dev" ;;
    esac
  fi

  if [[ -n "${DODO_VARIANT}" ]]; then
    case "${DODO_VARIANT}" in
      linux|lite) ;;
      *) error "Invalid --variant '${DODO_VARIANT}'. Must be: linux | lite" ;;
    esac
  fi

  if [[ -n "${DODO_ENDPOINT}" ]]; then
    if ! [[ "${DODO_ENDPOINT}" =~ ^[a-zA-Z0-9._-]+:[0-9]+$ ]]; then
      error "Invalid --endpoint '${DODO_ENDPOINT}'. Expected format: hostname:port"
    fi
  fi

  if [[ -n "${DODO_ENROLLMENT_ENDPOINT}" ]]; then
    if ! [[ "${DODO_ENROLLMENT_ENDPOINT}" =~ ^https://[a-zA-Z0-9._-]+(:[0-9]+)?/.+ ]]; then
      error "Invalid --enrollment-endpoint '${DODO_ENROLLMENT_ENDPOINT}'. Expected format: https://hostname[:port]/path"
    fi
  fi

  if [[ -n "${DODO_NAMESPACE}" ]]; then
    if ! [[ "${DODO_NAMESPACE}" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]]; then
      error "Invalid --namespace '${DODO_NAMESPACE}'. Must be lowercase alphanumeric with hyphens."
    fi
  fi
}

# ─── Platform Detection ───────────────────────────────────────────────────────

ARCH=""
DODO_OS=""

detect_platform() {
  DODO_OS="$(uname -s)"

  case "$(uname -m)" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) error "Unsupported architecture: $(uname -m)" ;;
  esac

  if [[ -z "${DODO_VARIANT}" ]]; then
    local total_ram=9999
    if [[ -f /proc/meminfo ]]; then
      total_ram=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
    fi

    if [[ "${total_ram}" -lt 512 ]] || grep -qi "raspberry\|jetson\|orangepi" /proc/device-tree/model 2>/dev/null; then
      DODO_VARIANT="lite"
      info "Detected IoT/edge device — selecting lite variant (no eBPF, <20MB RAM)"
    else
      DODO_VARIANT="linux"
    fi
  fi
}

# ─── Enrollment Endpoint Derivation ───────────────────────────────────────────

# Known production gRPC endpoint whose enrollment endpoint we can safely infer.
readonly PROD_GRPC_ENDPOINT="kong.aegisops.io:443"
readonly PROD_ENROLLMENT_ENDPOINT="https://kong.aegisops.io:443/v1/enroll"

# Populates DODO_ENROLLMENT_ENDPOINT if not already set via --enrollment-endpoint.
#
# We deliberately do NOT derive the enrollment host from DODO_ENDPOINT's host in
# the general case: gRPC ingest and HTTPS enrollment are not guaranteed to share
# a hostname per environment (e.g. staging uses grpc.staging.oppervision.com.br
# for gRPC but api.staging.oppervision.com.br for enrollment, to keep ALPN
# unambiguous between h2/grpcs and https on Kong). Only the known production
# default is safe to infer automatically.
derive_enrollment_endpoint() {
  if [[ -n "${DODO_ENROLLMENT_ENDPOINT}" ]]; then
    return 0
  fi

  if [[ "${DODO_ENDPOINT}" == "${PROD_GRPC_ENDPOINT}" ]]; then
    DODO_ENROLLMENT_ENDPOINT="${PROD_ENROLLMENT_ENDPOINT}"
    return 0
  fi

  if [[ "${DODO_NON_INTERACTIVE}" == "true" ]]; then
    error "Custom --endpoint '${DODO_ENDPOINT}' has no known matching enrollment endpoint. Pass --enrollment-endpoint explicitly (gRPC ingest and HTTPS enrollment can live on different hostnames per environment)."
  fi

  warn "Custom endpoint detected — enrollment endpoint cannot be safely guessed (gRPC and enrollment hosts can differ per environment)."
  prompt_if_empty DODO_ENROLLMENT_ENDPOINT "Enrollment endpoint (full HTTPS URL, e.g. https://api.example.com/v1/enroll)" ""
  [[ -n "${DODO_ENROLLMENT_ENDPOINT}" ]] || error "Enrollment endpoint is required for a custom --endpoint."
}

# ─── Input Prompt Helpers ─────────────────────────────────────────────────────

# Non-interactive mode is automatically set when stdin is not a TTY
# (e.g. piped through curl | bash)
maybe_force_non_interactive() {
  if [[ ! -t 0 ]] && [[ "${DODO_NON_INTERACTIVE}" != "true" ]]; then
    DODO_NON_INTERACTIVE=true
  fi
}

# prompt_if_empty VAR_NAME "Prompt text" [default] [secret:true/false]
prompt_if_empty() {
  local var_name="$1"
  local prompt_text="$2"
  local default_val="${3:-}"
  local secret="${4:-false}"

  local current_val
  current_val="$(eval echo "\"\${${var_name}}\"")"

  if [[ -n "${current_val}" ]]; then
    return 0
  fi

  if [[ "${DODO_NON_INTERACTIVE}" == "true" ]]; then
    if [[ -n "${default_val}" ]]; then
      eval "${var_name}=\"\${default_val}\""
    fi
    return 0
  fi

  local input=""
  if [[ "${secret}" == "true" ]]; then
    set +x
    if [[ -n "${default_val}" ]]; then
      read -rsp "  ${prompt_text} [${default_val}]: " input
    else
      read -rsp "  ${prompt_text}: " input
    fi
    printf "\n"
    set -x 2>/dev/null || true
  else
    if [[ -n "${default_val}" ]]; then
      read -rp "  ${prompt_text} [${default_val}]: " input
    else
      read -rp "  ${prompt_text}: " input
    fi
  fi

  eval "${var_name}=\"\${input:-\${default_val}}\""
}

# ─── Interactive Mode Wizard ──────────────────────────────────────────────────

interactive_wizard() {
  if [[ -n "${DODO_MODE}" ]]; then
    return 0
  fi

  if [[ "${DODO_NON_INTERACTIVE}" == "true" ]]; then
    error "--mode is required in non-interactive mode. Use: --mode server | k8s | dev"
  fi

  printf "\n"
  printf "${BOLD}  DoDo AegisOps Agent Installer${RESET}  v${SCRIPT_VERSION}\n"
  printf "\n"
  printf "  Select installation mode:\n\n"
  printf "    ${BOLD}1) server${RESET}  — bare metal / VM (requires sudo, installs systemd service)\n"
  printf "    ${BOLD}2) k8s${RESET}     — Kubernetes cluster (deploys DaemonSet via Helm)\n"
  printf "    ${BOLD}3) dev${RESET}     — local Docker (test OTEL / dodo_sdk_go before prod)\n"
  printf "\n"
  read -rp "  Mode [1/2/3]: " _choice
  case "${_choice}" in
    1|server) DODO_MODE="server" ;;
    2|k8s)    DODO_MODE="k8s" ;;
    3|dev)    DODO_MODE="dev" ;;
    *) error "Invalid choice: ${_choice}" ;;
  esac
  printf "\n"
}

# ─── Dependency Checks ────────────────────────────────────────────────────────

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || error "Required command '$1' not found. Install it and retry."
}

check_deps_server() {
  require_cmd curl
  require_cmd tar
  require_cmd sha256sum
  [[ $EUID -eq 0 ]] || error "Server mode requires root. Run with: sudo bash get.sh --mode server"
  if ! command -v systemctl >/dev/null 2>&1; then
    warn "systemd not found — service unit will be written but not enabled"
  fi
}

check_deps_k8s() {
  require_cmd kubectl
  require_cmd helm
  kubectl cluster-info >/dev/null 2>&1 || \
    error "kubectl cannot reach the cluster. Check your kubeconfig and try again."
}

check_deps_dev() {
  require_cmd docker
  docker info >/dev/null 2>&1 || \
    error "Docker daemon is not running. Start Docker Desktop or the Docker service and retry."
}

# ─── Binary Download ──────────────────────────────────────────────────────────

_download_binary() {
  local bin_name="aegis-agent"
  [[ "${DODO_VARIANT}" == "lite" ]] && bin_name="aegis-agent-lite"

  local archive="${bin_name}-${ARCH}.tar.gz"
  local base_url
  if [[ "${DODO_VERSION}" == "latest" ]]; then
    base_url="${GITHUB_RELEASES_BASE}/latest/download"
  else
    base_url="${GITHUB_RELEASES_BASE}/download/${DODO_VERSION}"
  fi

  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp}"' EXIT

  info "Downloading ${archive} from GitHub Releases..."
  if ! curl -fSL "${base_url}/${archive}" -o "${tmp}/archive.tar.gz" 2>/dev/null; then
    error "Download failed. Check that version '${DODO_VERSION}' exists at ${base_url}"
  fi

  if curl -fsSL "${base_url}/${archive}.sha256" -o "${tmp}/check.sha256" 2>/dev/null; then
    info "Verifying checksum..."
    (cd "${tmp}" && printf '%s  archive.tar.gz\n' "$(cat check.sha256)" | sha256sum -c -)
    ok "Checksum verified"
  else
    warn "Checksum file not available — skipping verification"
  fi

  tar -xzf "${tmp}/archive.tar.gz" -C "${tmp}"
  install -m 755 "${tmp}/${bin_name}" "${INSTALL_DIR}/aegis-agent"
  ok "Binary installed: ${INSTALL_DIR}/aegis-agent"
}

# ─── Config Writers ───────────────────────────────────────────────────────────

_write_server_config() {
  if [[ -f "${CONFIG_DIR}/agent.yaml" ]]; then
    warn "Config already exists — backing up to agent.yaml.bak"
    cp "${CONFIG_DIR}/agent.yaml" "${CONFIG_DIR}/agent.yaml.bak"
  fi

  cat > "${CONFIG_DIR}/agent.yaml" << YAML
# AegisOps Agent Configuration
# Generated by get.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)
# API key is loaded from /etc/aegis/agent.env — do not put it here.

endpoint:
  address: "${DODO_ENDPOINT}"
  timeout_ms: 5000
  retry_max: 3
  retry_backoff_ms: 1000

tls:
  ca_cert_path: "${CERTS_DIR}/ca.pem"
  client_cert_path: "${CERTS_DIR}/agent.pem"
  client_key_path: "${CERTS_DIR}/agent-key.pem"
  verify_server: true

# mTLS certificates are obtained automatically on first start via
# certificate auto-enrollment (POST to enrollment_endpoint using the API key
# in /etc/aegis/agent.env) — no manual certificate placement needed. Leave
# empty to disable auto-enrollment and manage certificates manually instead.
enrollment_endpoint: "${DODO_ENROLLMENT_ENDPOINT}"

buffer:
  path: "${BUFFER_DIR}"
  max_size_bytes: 536870912
  flush_interval_ms: 5000
  max_batch_size: 500

logging:
  level: "info"
  output: "stdout"
  file_path: ""

config_pull_interval_seconds: 60
agent_id_path: "${DATA_DIR}/agent_id"

labels:
  environment: "production"

redaction_patterns: []

collectors:
  - name: cpu
    enabled: true
    interval_seconds: 5

  - name: memory
    enabled: true
    interval_seconds: 5

  - name: disk
    enabled: true
    interval_seconds: 10

  - name: network
    enabled: true
    interval_seconds: 5

  - name: process
    enabled: true
    interval_seconds: 10

  - name: security
    enabled: true
    interval_seconds: 15
    parameters:
      monitored_files: "/etc/passwd,/etc/shadow,/etc/sudoers,/etc/ssh/sshd_config"

  - name: certs
    enabled: true
    interval_seconds: 3600
    parameters:
      scan_paths: "/etc/ssl/certs,/etc/pki/tls/certs"

  - name: logs
    enabled: true
    interval_seconds: 1
    parameters:
      paths: "/var/log/syslog,/var/log/messages"
      max_line_bytes: "16384"

  - name: otel
    enabled: false
    interval_seconds: 1

  - name: kubernetes
    enabled: false
    interval_seconds: 15

  - name: inventory
    enabled: true
    interval_seconds: 3600

  - name: self_metrics
    enabled: true
    interval_seconds: 30

  - name: heartbeat
    enabled: true
    interval_seconds: 30

  - name: docker
    enabled: true
    interval_seconds: 10

  - name: postgres
    enabled: false
    interval_seconds: 15

  - name: mongodb
    enabled: false
    interval_seconds: 15

  - name: redis
    enabled: false
    interval_seconds: 10
YAML
  ok "Config written: ${CONFIG_DIR}/agent.yaml"
}

_write_dev_config() {
  local config_file="$1"

  cat > "${config_file}" << YAML
# AegisOps Agent — Dev Mode Configuration
# Generated by get.sh (dev mode) on $(date -u +%Y-%m-%dT%H:%M:%SZ)
# WARNING: TLS disabled, security collectors off. Do NOT use in production.

endpoint:
  address: "${DODO_ENDPOINT}"
  timeout_ms: 5000
  retry_max: 3
  retry_backoff_ms: 1000

tls:
  enabled: false
  ca_cert_path: ""
  client_cert_path: ""
  client_key_path: ""
  verify_server: false

buffer:
  path: "/tmp/aegis-buffer"
  max_size_bytes: 52428800
  flush_interval_ms: 5000
  max_batch_size: 100

logging:
  level: "info"
  output: "stdout"
  file_path: ""

config_pull_interval_seconds: 0
agent_id_path: "/tmp/aegis-agent-id"

labels:
  environment: "dev"

redaction_patterns: []

collectors:
  - name: cpu
    enabled: true
    interval_seconds: 10

  - name: memory
    enabled: true
    interval_seconds: 10

  - name: disk
    enabled: true
    interval_seconds: 30

  - name: network
    enabled: true
    interval_seconds: 10

  - name: process
    enabled: true
    interval_seconds: 15

  - name: heartbeat
    enabled: true
    interval_seconds: 30

  - name: self_metrics
    enabled: true
    interval_seconds: 30

  - name: inventory
    enabled: true
    interval_seconds: 3600

  - name: docker
    enabled: true
    interval_seconds: 10

  # OTEL passthrough — the main purpose of dev mode.
  # Listens on :4317 (gRPC) and :4318 (HTTP) inside the container,
  # mapped to host ports by docker run -p flags.
  - name: otel
    enabled: true
    interval_seconds: 1

  # Disabled in dev — no eBPF, no TLS certs, no /var/log inside container.
  - name: kubernetes
    enabled: false
    interval_seconds: 15

  - name: security
    enabled: false
    interval_seconds: 15

  - name: certs
    enabled: false
    interval_seconds: 3600

  - name: logs
    enabled: false
    interval_seconds: 1

  - name: postgres
    enabled: false
    interval_seconds: 15

  - name: mongodb
    enabled: false
    interval_seconds: 15

  - name: redis
    enabled: false
    interval_seconds: 10
YAML
  ok "Dev config written: ${config_file}"
}

_write_agent_env() {
  set +x
  cat > "${CONFIG_DIR}/agent.env" << ENV
DODO_API_KEY=${DODO_API_KEY}
ENV
  set -x 2>/dev/null || true
  chmod 600 "${CONFIG_DIR}/agent.env"
  chown "root:${SERVICE_USER}" "${CONFIG_DIR}/agent.env" 2>/dev/null || true
  ok "Agent env file written: ${CONFIG_DIR}/agent.env (mode 600)"
}

_write_systemd_unit() {
  cat > /etc/systemd/system/aegis-agent.service << 'UNIT'
[Unit]
Description=DoDo AegisOps Agent - Telemetry Collection
Documentation=https://docs.aegisops.io/agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=aegis-agent
Group=aegis-agent
ExecStart=/usr/local/bin/aegis-agent
Restart=always
RestartSec=5
TimeoutStopSec=15

WorkingDirectory=/var/lib/aegis

Environment=AEGIS_CONFIG=/etc/aegis/agent.yaml
Environment=RUST_LOG=info
EnvironmentFile=/etc/aegis/agent.env

LimitNOFILE=65536
LimitMEMLOCK=infinity

ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/aegis /var/log/aegis
ReadOnlyPaths=/etc/aegis
PrivateTmp=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native

AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_NET_RAW CAP_DAC_READ_SEARCH
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_RAW CAP_DAC_READ_SEARCH

[Install]
WantedBy=multi-user.target
UNIT
  ok "Systemd unit installed: /etc/systemd/system/aegis-agent.service"
}

# ─── Mode: server ─────────────────────────────────────────────────────────────

server() {
  step "Server Mode — Bare Metal / VM Install"
  check_deps_server

  prompt_if_empty DODO_API_KEY  "API Key"                          ""                     "true"
  prompt_if_empty DODO_ENDPOINT "AegisOps gRPC endpoint"          "kong.aegisops.io:443"
  prompt_if_empty DODO_VERSION  "Agent version"                   "latest"

  [[ -n "${DODO_API_KEY}" ]] || error "API key is required for server mode. Use --api-key or set DODO_API_KEY."

  derive_enrollment_endpoint

  step "Creating system user '${SERVICE_USER}'"
  if ! id "${SERVICE_USER}" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
    ok "User '${SERVICE_USER}' created"
  else
    ok "User '${SERVICE_USER}' already exists"
  fi

  step "Creating directories"
  mkdir -p "${INSTALL_DIR}" "${CONFIG_DIR}" "${CERTS_DIR}" \
           "${DATA_DIR}" "${BUFFER_DIR}" "${LOG_DIR}"
  ok "Directories ready"

  step "Downloading agent binary (variant=${DODO_VARIANT}, arch=${ARCH}, version=${DODO_VERSION})"
  _download_binary

  step "Setting file capabilities"
  if command -v setcap >/dev/null 2>&1; then
    if setcap 'cap_bpf,cap_perfmon,cap_net_raw,cap_dac_read_search=eip' \
        "${INSTALL_DIR}/aegis-agent" 2>/dev/null; then
      ok "Capabilities set (CAP_BPF, CAP_PERFMON, CAP_NET_RAW, CAP_DAC_READ_SEARCH)"
    else
      warn "setcap failed — agent will run as root or with reduced collector coverage"
    fi
  else
    warn "setcap not found. Install libcap2-bin (Debian/Ubuntu) or libcap (RHEL) for proper capabilities."
  fi

  step "Writing configuration"
  _write_server_config
  _write_agent_env

  step "Setting permissions"
  # CERTS_DIR lives under DATA_DIR, so this recursive chown also covers it —
  # the agent process (running as SERVICE_USER) needs write access there to
  # perform mTLS auto-enrollment on first start.
  chown -R "${SERVICE_USER}:${SERVICE_USER}" "${DATA_DIR}" "${LOG_DIR}"
  chown -R "root:${SERVICE_USER}" "${CONFIG_DIR}"
  chmod 750 "${CONFIG_DIR}"
  chmod 640 "${CONFIG_DIR}/agent.yaml"
  chmod 700 "${CERTS_DIR}"
  ok "Permissions set"

  if command -v systemctl >/dev/null 2>&1; then
    step "Installing systemd service"
    _write_systemd_unit
    systemctl daemon-reload
    systemctl enable aegis-agent
    ok "Service enabled (aegis-agent)"
  fi

  verify_server
}

verify_server() {
  step "Post-Install Verification"

  printf "\n${BOLD}Binary checksum:${RESET}\n"
  sha256sum "${INSTALL_DIR}/aegis-agent"

  local service_started=false
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl start aegis-agent 2>/dev/null; then
      service_started=true
    else
      warn "Service failed to start — check: systemctl status aegis-agent"
    fi
  fi

  # `systemctl is-active` alone doesn't prove enrollment succeeded: the agent
  # process stays up and just buffers to disk indefinitely if enrollment
  # keeps failing. Poll for the enrolled certificate instead — timeout covers
  # enroll_with_retry's worst case (6 attempts, backoff up to 15s each) with
  # margin.
  if [[ "${service_started}" == "true" ]]; then
    step "Waiting for automatic mTLS certificate enrollment"
    local attempts=0 max=35
    while [[ ! -f "${CERTS_DIR}/agent.pem" ]]; do
      attempts=$((attempts + 1))
      if [[ "${attempts}" -ge "${max}" ]]; then
        break
      fi
      sleep 2
    done

    if [[ -f "${CERTS_DIR}/agent.pem" ]]; then
      ok "Agent enrolled — mTLS certificates written to ${CERTS_DIR}/"
    else
      warn "No certificates found yet after $((max * 2))s."
      warn "Check enrollment logs: journalctl -u aegis-agent -f | grep -i enroll"
    fi

    if systemctl is-active --quiet aegis-agent; then
      ok "Service is running"
    else
      warn "Service is not active — check: systemctl status aegis-agent"
    fi
  fi

  printf "\n${BOLD}Next steps:${RESET}\n"
  printf "  1. Enrollment is automatic — the agent used the API key in\n"
  printf "     ${CONFIG_DIR}/agent.env to self-enroll mTLS certificates on first start.\n"
  printf "     No manual certificate placement is needed.\n"
  printf "  2. Check status:      systemctl status aegis-agent\n"
  printf "  3. Follow logs:       journalctl -u aegis-agent -f\n"
  printf "  4. If enrollment failed, verify the API key and enrollment endpoint:\n"
  printf "       cat ${CONFIG_DIR}/agent.env      (redact before sharing)\n"
  printf "       grep enrollment_endpoint ${CONFIG_DIR}/agent.yaml\n"
  printf "     then restart:       systemctl restart aegis-agent\n"
  printf "  5. To manage certificates manually instead (e.g. air-gapped hosts),\n"
  printf "     set enrollment_endpoint: \"\" in ${CONFIG_DIR}/agent.yaml and place\n"
  printf "     ca.pem / agent.pem / agent-key.pem in ${CERTS_DIR}/ yourself.\n"
  printf "\n"
}

# ─── Mode: k8s ────────────────────────────────────────────────────────────────

_helm_deploy() {
  local helm_args=(
    "--namespace" "${DODO_NAMESPACE}"
    "--set" "agent.ingestorEndpoint=${DODO_ENDPOINT}"
    "--set" "agent.labels.environment=production"
    "--wait"
    "--timeout" "120s"
  )

  if [[ "${DODO_VERSION}" != "latest" ]]; then
    helm_args+=("--version" "${DODO_VERSION}")
  fi

  if [[ -n "${DODO_TLS_SECRET}" ]]; then
    # Static/pre-provisioned certs (e.g. air-gapped clusters) — takes
    # precedence over self-enrollment in the chart's own logic, but we still
    # pass the enrollment values below; the chart ignores them when
    # tls.secretName is set.
    helm_args+=("--set" "tls.secretName=${DODO_TLS_SECRET}")
  fi

  # Self-enrollment: the API key secret was already created by k8s() above.
  # The chart uses it to auto-enroll mTLS certs unless DODO_TLS_SECRET (a
  # static secret) was provided instead.
  helm_args+=(
    "--set" "apiKey.secretName=aegis-agent-credentials"
    "--set" "apiKey.secretKey=api-key"
    "--set" "enrollment.endpoint=${DODO_ENROLLMENT_ENDPOINT}"
  )

  info "Trying OCI registry..."
  if helm upgrade --install aegis-agent "${HELM_OCI_CHART}" "${helm_args[@]}" 2>/dev/null; then
    ok "Deployed via OCI registry"
    return 0
  fi

  warn "OCI deploy failed — falling back to Helm repository..."
  helm repo add "${HELM_REPO_NAME}" "${HELM_REPO_URL}" 2>/dev/null || true
  helm repo update "${HELM_REPO_NAME}"
  helm upgrade --install aegis-agent "${HELM_REPO_NAME}/aegis-agent" "${helm_args[@]}"
  ok "Deployed via Helm repository"
}

k8s() {
  step "Kubernetes Mode — Cluster DaemonSet Deploy"
  check_deps_k8s

  prompt_if_empty DODO_API_KEY    "API Key"                                ""                     "true"
  prompt_if_empty DODO_ENDPOINT   "gRPC endpoint"                         "kong.aegisops.io:443"
  prompt_if_empty DODO_NAMESPACE  "Kubernetes namespace"                  "dodo"
  prompt_if_empty DODO_TLS_SECRET "Static TLS secret name (leave blank to self-enroll automatically)" ""

  [[ -n "${DODO_API_KEY}" ]] || error "API key is required. Use --api-key or set DODO_API_KEY."

  derive_enrollment_endpoint

  local ctx
  ctx="$(kubectl config current-context 2>/dev/null || echo 'unknown')"
  printf "\n  ${BOLD}Target cluster context:${RESET} ${YELLOW}${ctx}${RESET}\n"
  if [[ "${DODO_NON_INTERACTIVE}" != "true" ]]; then
    read -rp "  Proceed with this context? [y/N]: " _confirm
    [[ "${_confirm}" =~ ^[Yy]$ ]] || error "Aborted by user"
  fi

  step "Ensuring namespace '${DODO_NAMESPACE}'"
  kubectl get namespace "${DODO_NAMESPACE}" >/dev/null 2>&1 \
    || kubectl create namespace "${DODO_NAMESPACE}"
  ok "Namespace ready"

  step "Creating API key secret"
  kubectl -n "${DODO_NAMESPACE}" create secret generic aegis-agent-credentials \
    --from-literal=api-key="${DODO_API_KEY}" \
    --dry-run=client -o yaml | kubectl apply -f -
  ok "Secret 'aegis-agent-credentials' applied"

  step "Deploying via Helm (version=${DODO_VERSION})"
  _helm_deploy

  verify_k8s
}

verify_k8s() {
  step "Post-Deploy Verification"
  info "Waiting for pods..."
  sleep 5

  kubectl -n "${DODO_NAMESPACE}" get pods -l app.kubernetes.io/name=aegis-agent || true

  local desired ready
  desired=$(kubectl -n "${DODO_NAMESPACE}" get daemonset aegis-agent \
    -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || echo "?")
  ready=$(kubectl -n "${DODO_NAMESPACE}" get daemonset aegis-agent \
    -o jsonpath='{.status.numberReady}' 2>/dev/null || echo "?")
  info "DaemonSet: ${ready}/${desired} pods ready"

  printf "\n${BOLD}Useful commands:${RESET}\n"
  printf "  Watch pods:   kubectl -n %s get pods -l app.kubernetes.io/name=aegis-agent -w\n" "${DODO_NAMESPACE}"
  printf "  Agent logs:   kubectl -n %s logs -l app.kubernetes.io/name=aegis-agent -f\n" "${DODO_NAMESPACE}"
  printf "  DaemonSet:    kubectl -n %s describe daemonset aegis-agent\n" "${DODO_NAMESPACE}"

  if [[ -z "${DODO_TLS_SECRET}" ]]; then
    printf "\n${BOLD}mTLS:${RESET} no static secret given — agents self-enroll automatically\n"
    printf "using the 'aegis-agent-credentials' API key secret. Verify with:\n"
    printf "  kubectl -n %s exec ds/aegis-agent -- ls /var/lib/aegis-agent/certs\n" "${DODO_NAMESPACE}"
    printf "  kubectl -n %s logs -l app.kubernetes.io/name=aegis-agent | grep -i enroll\n" "${DODO_NAMESPACE}"
    printf "\n${BOLD}Air-gapped alternative:${RESET} to use pre-provisioned certificates instead,\n"
    printf "skip self-enrollment with a static secret:\n"
    printf "  kubectl -n %s create secret generic aegis-tls \\\\\n" "${DODO_NAMESPACE}"
    printf "    --from-file=ca.crt=ca.pem \\\\\n"
    printf "    --from-file=tls.crt=agent.pem \\\\\n"
    printf "    --from-file=tls.key=agent-key.pem\n"
    printf "  helm upgrade aegis-agent aegisops/aegis-agent -n %s --set tls.secretName=aegis-tls\n" "${DODO_NAMESPACE}"
  fi
  printf "\n"
}

# ─── Mode: dev ────────────────────────────────────────────────────────────────

show_dev_guide() {
  printf "\n${BOLD}=== SDK Connection Guide ===${RESET}\n\n"

  printf "${BOLD}Agent listening on:${RESET}\n"
  printf "  OTEL gRPC   →  grpc://localhost:4317  (traces, metrics, logs)\n"
  printf "  OTEL HTTP   →  http://localhost:4318  (traces, metrics, logs)\n"
  printf "  Health      →  http://localhost:9090/healthz\n\n"

  printf "${BOLD}Go — dodo_sdk_go:${RESET}\n"
  printf "  import \"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc\"\n\n"
  printf "  exporter, _ := otlptracegrpc.New(ctx,\n"
  printf "      otlptracegrpc.WithEndpoint(\"localhost:4317\"),\n"
  printf "      otlptracegrpc.WithInsecure(),\n"
  printf "  )\n\n"

  printf "${BOLD}Go — standard env vars:${RESET}\n"
  printf "  export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318\n"
  printf "  export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf\n\n"

  printf "${BOLD}Python — opentelemetry-sdk:${RESET}\n"
  printf "  pip install opentelemetry-exporter-otlp\n\n"
  printf "  # gRPC\n"
  printf "  from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter\n"
  printf "  exporter = OTLPSpanExporter(endpoint=\"http://localhost:4317\", insecure=True)\n\n"
  printf "  # HTTP\n"
  printf "  from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter\n"
  printf "  exporter = OTLPSpanExporter(endpoint=\"http://localhost:4318/v1/traces\")\n\n"

  printf "${BOLD}Java / OpenTelemetry Agent:${RESET}\n"
  printf "  # gRPC\n"
  printf "  -Dotel.exporter.otlp.endpoint=http://localhost:4317\n"
  printf "  -Dotel.exporter.otlp.protocol=grpc\n\n"
  printf "  # HTTP/protobuf\n"
  printf "  -Dotel.exporter.otlp.endpoint=http://localhost:4318\n"
  printf "  -Dotel.exporter.otlp.protocol=http/protobuf\n\n"

  printf "${BOLD}Node.js — @opentelemetry/exporter-trace-otlp-grpc:${RESET}\n"
  printf "  const { OTLPTraceExporter } = require('@opentelemetry/exporter-trace-otlp-grpc');\n"
  printf "  const exporter = new OTLPTraceExporter({ url: 'http://localhost:4317' });\n\n"

  printf "${BOLD}Environment variables (any SDK):${RESET}\n"
  printf "  OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318\n"
  printf "  OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf\n\n"

  printf "${BOLD}Watch live telemetry arriving:${RESET}\n"
  printf "  docker logs -f aegis-agent-dev\n\n"

  printf "${BOLD}Stop the agent:${RESET}\n"
  printf "  docker rm -f aegis-agent-dev\n\n"

  printf "${BOLD}Restart with different settings:${RESET}\n"
  printf "  DODO_API_KEY=my-key DODO_ENDPOINT=sandbox.aegisops.io:443 \\\\\n"
  printf "    bash get.sh --mode dev --non-interactive\n\n"
}

dev() {
  step "Dev Mode — Local Docker (OTEL / SDK Testing)"
  check_deps_dev

  local default_dev_endpoint="sandbox.aegisops.io:443"
  prompt_if_empty DODO_API_KEY  "API Key (or press Enter for 'dev-key')" "dev-key" "true"
  prompt_if_empty DODO_ENDPOINT "Remote endpoint"                        "${default_dev_endpoint}"

  [[ -n "${DODO_API_KEY}" ]] || DODO_API_KEY="dev-key"

  local config_dir="${HOME}/.aegisops"
  local config_file="${config_dir}/agent-dev.yaml"
  local container_name="aegis-agent-dev"
  local docker_tag="${DODO_VERSION}"
  [[ "${docker_tag}" == "latest" ]] && docker_tag="latest"

  step "Writing dev configuration to ${config_file}"
  mkdir -p "${config_dir}"
  _write_dev_config "${config_file}"

  if docker inspect "${container_name}" >/dev/null 2>&1; then
    warn "Container '${container_name}' already running — stopping and replacing"
    docker rm -f "${container_name}" >/dev/null
  fi

  step "Pulling agent image (${DOCKER_IMAGE}:${docker_tag})"
  docker pull "${DOCKER_IMAGE}:${docker_tag}"

  step "Starting agent container"
  docker run -d \
    --name "${container_name}" \
    --restart unless-stopped \
    -p 4317:4317 \
    -p 4318:4318 \
    -p "${HEALTH_PORT}:${HEALTH_PORT}" \
    -v "${config_file}:/etc/aegis/agent.yaml:ro" \
    -e "AEGIS_CONFIG=/etc/aegis/agent.yaml" \
    -e "RUST_LOG=info" \
    -e "DODO_API_KEY=${DODO_API_KEY}" \
    "${DOCKER_IMAGE}:${docker_tag}"

  ok "Container started: ${container_name}"

  verify_dev
  show_dev_guide
}

verify_dev() {
  step "Verifying agent health"
  local attempts=0 max=10
  while ! curl -sf "http://localhost:${HEALTH_PORT}/healthz" >/dev/null 2>&1; do
    attempts=$((attempts + 1))
    if [[ "${attempts}" -ge "${max}" ]]; then
      warn "Health check timed out after $((max * 2))s — check logs: docker logs aegis-agent-dev"
      return 0
    fi
    printf "  waiting... (%d/%d)\n" "${attempts}" "${max}"
    sleep 2
  done

  local health_resp
  health_resp="$(curl -s "http://localhost:${HEALTH_PORT}/healthz" 2>/dev/null || echo 'ok')"
  ok "Agent healthy: ${health_resp}"
}

# ─── Entrypoint ───────────────────────────────────────────────────────────────

main() {
  parse_args "$@"
  maybe_force_non_interactive
  validate_inputs
  detect_platform

  printf "\n${BOLD}DoDo AegisOps Agent Installer${RESET} — v${SCRIPT_VERSION}\n"

  interactive_wizard

  case "${DODO_MODE}" in
    server) server ;;
    k8s)    k8s ;;
    dev)    dev ;;
    *) error "Unknown mode: '${DODO_MODE}'. Must be: server | k8s | dev" ;;
  esac

  printf "${GREEN}${BOLD}Done.${RESET}\n\n"
}

main "$@"
