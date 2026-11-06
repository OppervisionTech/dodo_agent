#!/usr/bin/env bash
# Canonical, versioned Linux installer. Published as both get.sh and install.sh.
# Supply endpoints from the environment's installation manifest; no legacy hosts.
set -euo pipefail
set +x
readonly GITHUB_REPO="OppervisionTech/dodo_agent"
readonly DOCKER_IMAGE="ghcr.io/oppervisiontech/aegis-agent"
DODO_MODE="${DODO_MODE:-server}"
DODO_API_KEY="${DODO_API_KEY:-}"
DODO_ENDPOINT="${DODO_ENDPOINT:-grpc.stg.dodo.oppervision.com.br:443}"
DODO_ENROLLMENT_ENDPOINT="${DODO_ENROLLMENT_ENDPOINT:-https://api.stg.dodo.oppervision.com.br/v1/enroll}"
DODO_VERSION="${DODO_VERSION:-}"
DODO_VARIANT="${DODO_VARIANT:-linux}"
INSTALL_TMP=""
error() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }
cleanup() { [[ -z "$INSTALL_TMP" ]] || rm -rf "$INSTALL_TMP"; }
trap cleanup EXIT

parse_args() {
  while (($#)); do
    local option="$1" value=""
    if [[ "$option" == *=* ]]; then value="${option#*=}"; option="${option%%=*}"; shift
    else
      case "$option" in
        --non-interactive) shift; continue ;;
        --help|-h) printf 'Usage: get.sh --version vX.Y.Z --endpoint host:443 --enrollment-endpoint https://host/v1/enroll [--api-key KEY] [--mode server|dev] [--variant linux|lite]\n'; return 0 ;;
      esac
      (($# >= 2)) && [[ "$2" != --* ]] || error "Missing value for $option"
      value="$2"; shift 2
    fi
    [[ -n "$value" ]] || error "Empty value for $option"
    case "$option" in
      --mode) DODO_MODE="$value" ;;
      --api-key) DODO_API_KEY="$value" ;;
      --endpoint) DODO_ENDPOINT="$value" ;;
      --enrollment-endpoint) DODO_ENROLLMENT_ENDPOINT="$value" ;;
      --version) DODO_VERSION="$value" ;;
      --variant) DODO_VARIANT="$value" ;;
      *) error "Unknown option: $option" ;;
    esac
  done
}
validate_inputs() {
  [[ "$DODO_MODE" == server || "$DODO_MODE" == dev ]] || error 'Supported modes: server, dev (Linux host-network Docker). Use the separately versioned chart for Kubernetes.'
  [[ "$DODO_VARIANT" == linux || "$DODO_VARIANT" == lite ]] || error 'Variant must be linux or lite'
  [[ "$DODO_VERSION" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?$ ]] || error 'An explicit published --version is required (vX.Y.Z)'
  [[ "$DODO_ENDPOINT" =~ ^[a-zA-Z0-9.-]+:[0-9]+$ ]] || error 'An explicit --endpoint host:port is required'
  [[ "$DODO_ENROLLMENT_ENDPOINT" =~ ^https://[a-zA-Z0-9.-]+(:[0-9]+)?/v1/enroll$ ]] || error 'An explicit HTTPS --enrollment-endpoint ending /v1/enroll is required'
  [[ "$DODO_API_KEY" =~ ^dodo_[a-fA-F0-9]{64}$ ]] || error 'A valid DODO_API_KEY or --api-key is required'
  DODO_VERSION="v${DODO_VERSION#v}"
}
verify_checksum() {
  local archive="$1" checksum_file="$2" expected actual
  expected="$(awk 'NR==1 {print $1}' "$checksum_file")"
  [[ "$expected" =~ ^[a-fA-F0-9]{64}$ ]] || error 'Invalid SHA256 checksum file'
  actual="$(sha256sum "$archive")"; actual="${actual%% *}"
  [[ "$(printf %s "$actual" | tr A-F a-f)" == "$(printf %s "$expected" | tr A-F a-f)" ]] || error 'SHA256 mismatch; refusing installation'
}
download_binary() {
  local arch="$1" variant="aegis-agent-linux" binary="aegis-agent"
  if [[ "$DODO_VARIANT" == lite ]]; then variant="aegis-agent-lite"; binary="aegis-agent-lite"; fi
  local archive="${variant}-${arch}.tar.gz"
  local base="https://github.com/${GITHUB_REPO}/releases/download/${DODO_VERSION}"
  INSTALL_TMP="$(mktemp -d)"
  curl --proto '=https' --tlsv1.2 -fsSL "$base/$archive" -o "$INSTALL_TMP/archive.tar.gz"
  curl --proto '=https' --tlsv1.2 -fsSL "$base/$archive.sha256" -o "$INSTALL_TMP/check.sha256"
  verify_checksum "$INSTALL_TMP/archive.tar.gz" "$INSTALL_TMP/check.sha256"
  [[ "$(tar -tzf "$INSTALL_TMP/archive.tar.gz")" == "$binary" ]] || error 'Unexpected archive contents'
  tar -xzf "$INSTALL_TMP/archive.tar.gz" -C "$INSTALL_TMP"
  [[ -f "$INSTALL_TMP/$binary" && ! -L "$INSTALL_TMP/$binary" ]] || error 'Archive does not contain a regular binary'
  install -m 755 "$INSTALL_TMP/$binary" /usr/local/bin/aegis-agent
}
write_config() {
  local dir="$1"
  mkdir -p "$dir"
  cat > "$dir/agent.yaml" <<YAML
endpoint:
  address: "$DODO_ENDPOINT"
enrollment_endpoint: "$DODO_ENROLLMENT_ENDPOINT"
tls:
  enabled: true
  ca_cert_path: /var/lib/aegis/certs/ca.pem
  client_cert_path: /var/lib/aegis/certs/agent.pem
  client_key_path: /var/lib/aegis/certs/agent-key.pem
  verify_server: true
buffer:
  path: /var/lib/aegis/buffer
agent_id_path: /var/lib/aegis/agent_id
collectors:
  - {name: cpu, enabled: true, interval_seconds: 5}
  - {name: memory, enabled: true, interval_seconds: 5}
  - {name: disk, enabled: true, interval_seconds: 10}
  - {name: network, enabled: true, interval_seconds: 5}
  - {name: inventory, enabled: true, interval_seconds: 3600}
  - {name: heartbeat, enabled: true, interval_seconds: 30}
  - {name: self_metrics, enabled: true, interval_seconds: 30}
  - {name: otel, enabled: true, interval_seconds: 1}
YAML
  (umask 077; printf 'DODO_API_KEY=%s\n' "$DODO_API_KEY" > "$dir/agent.env")
}
write_unit() {
  cat > /etc/systemd/system/aegis-agent.service <<'UNIT'
[Unit]
Description=DoDo AegisOps Agent
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=aegis-agent
Group=aegis-agent
ExecStart=/usr/local/bin/aegis-agent
WorkingDirectory=/var/lib/aegis
Environment=AEGIS_CONFIG=/etc/aegis/agent.yaml
EnvironmentFile=/etc/aegis/agent.env
Restart=always
RestartSec=5
TimeoutStopSec=15
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
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT
}
main() {
  if [[ "${1:-}" == --help || "${1:-}" == -h ]]; then parse_args "$1"; return; fi
  parse_args "$@"
  validate_inputs
  [[ "$(uname -s)" == Linux ]] || error 'This installer requires Linux. Docker Desktop requires an explicitly supported collector deployment.'
  local arch
  case "$(uname -m)" in x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) error 'Unsupported architecture' ;; esac
  if [[ "$DODO_MODE" == dev ]]; then
    [[ "$DODO_VARIANT" == linux ]] || error 'Docker mode supports the standard image'
    command -v docker >/dev/null || error 'Docker is required'
    local config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/dodo-agent"
    (umask 077; write_config "$config_dir")
    docker volume create dodo-agent-data >/dev/null
    docker run -d --name dodo-agent --restart unless-stopped --network host \
      --env-file "$config_dir/agent.env" -v "$config_dir:/etc/aegis:ro" \
      -v dodo-agent-data:/var/lib/aegis "$DOCKER_IMAGE:${DODO_VERSION#v}"
    printf 'Local collector: http://127.0.0.1:4318/healthz. State persists in dodo-agent-data.\n'
    return
  fi
  [[ "$EUID" == 0 ]] || error 'Server mode requires root (sudo)'
  for cmd in curl tar sha256sum systemctl useradd; do command -v "$cmd" >/dev/null || error "Missing dependency: $cmd"; done
  # Validate/download before changing service configuration. A failed artifact does
  # not stop a previously healthy agent.
  download_binary "$arch"
  id aegis-agent >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin aegis-agent
  install -d -m 750 -o root -g aegis-agent /etc/aegis
  install -d -m 700 -o aegis-agent -g aegis-agent /var/lib/aegis /var/lib/aegis/certs /var/lib/aegis/buffer /var/log/aegis
  # Upgrade legacy cert locations without changing the enrolled key/identity.
  for name in ca.pem agent.pem agent-key.pem; do
    if [[ ! -e /var/lib/aegis/certs/$name && -f /etc/aegis/certs/$name && ! -L /etc/aegis/certs/$name ]]; then
      install -m 600 -o aegis-agent -g aegis-agent "/etc/aegis/certs/$name" "/var/lib/aegis/certs/$name"
    fi
  done
  write_config /etc/aegis
  chown root:aegis-agent /etc/aegis/agent.yaml /etc/aegis/agent.env
  chmod 640 /etc/aegis/agent.yaml
  chmod 600 /etc/aegis/agent.env
  write_unit
  systemctl daemon-reload
  systemctl enable --now aegis-agent
  systemctl restart aegis-agent
  printf 'Installed %s. Diagnose: systemctl status aegis-agent; journalctl -u aegis-agent. Collector health: http://127.0.0.1:4318/healthz (not proof of backend delivery).\n' "$DODO_VERSION"
}
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
