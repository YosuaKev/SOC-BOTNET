#!/usr/bin/env bash
set -Eeuo pipefail

VERSION="1.3.1"
INSTALL_DIR="/opt/zeek-botnet-detector"
DETECTOR_USER="zeekbot"
DETECTOR_GROUP="zeekbot"
PYTHON_VERSION="3.12"
INTERFACE=""
BEHAVIOR_WINDOW=60
HTTP_THRESHOLD=20
SSH_THRESHOLD=10
PORT_THRESHOLD=15
HOST_THRESHOLD=15
FLOOD_WINDOW=10
FLOOD_THRESHOLD=100
BEACON_WINDOW=600
BEACON_MIN_CONNECTIONS=6
BEACON_MIN_INTERVAL=5
BEACON_MAX_INTERVAL=300
BEACON_MAX_CV=0.15
BEHAVIOR_COOLDOWN=60
IGNORE_SERVICES=()
SHIP_ALL_PREDICTIONS=0
SKIP_ZEEK_INSTALL=0
SKIP_FILEBEAT=0
ELASTIC_MAJOR="9"
ES_HOST="https://10.70.128.26:9200"
ES_USER="elastic"
ES_PASSWORD_FILE=""
ES_CA_CERT=""
ES_INSECURE=1
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PAYLOAD_DIR="$SCRIPT_DIR/payload"
MODEL_SRC="$PAYLOAD_DIR/models/rf_official_bro_final_pipeline.joblib"
CONFIG_SRC="$PAYLOAD_DIR/models/zeek_official_active_feature_config.pkl"
FEATURE_SRC="$PAYLOAD_DIR/src/feature_engineering.py"
DETECTOR_SRC="$PAYLOAD_DIR/src/detector.py"
BEHAVIOR_SRC="$PAYLOAD_DIR/src/behavior_detector.py"
MONITOR_SRC="$PAYLOAD_DIR/src/monitor.sh"
INSTALL_LOG="/var/log/zeek-botnet-installer.log"
RUNTIME_CONF="/etc/zeek-botnet-detector.conf"
FILEBEAT_CONFIG_DIR="/etc/filebeat-botnet"
FILEBEAT_CONFIG="$FILEBEAT_CONFIG_DIR/filebeat.yml"
FILEBEAT_SERVICE="/etc/systemd/system/filebeat-botnet.service"
FILEBEAT_DATA="/var/lib/filebeat-botnet"
FILEBEAT_LOGS="/var/log/filebeat-botnet"
FILEBEAT_KEYSTORE="$FILEBEAT_CONFIG_DIR/filebeat.keystore"
TS="$(date '+%Y%m%d-%H%M%S')"
ES_PASSWORD="${ES_PASSWORD:-}"

usage() {
  cat <<USAGE
Zeek Botnet + Behavior + Isolated Filebeat Installer v$VERSION

NO Zeek source compilation is performed. Zeek is installed only with apt/dnf/yum packages.
The existing /etc/filebeat/filebeat.yml and filebeat.service are NEVER modified.

Usage:
  sudo ./install.sh [options]

Core options:
  --interface IFACE             Zeek capture interface. Default: default-route interface.
  --skip-zeek-install           Require an existing Zeek installation; do not install packages.
  --behavior-window SEC         General brute-force/scan window (default: 60).
  --http-threshold N            HTTP login POST threshold/window (default: 20).
  --ssh-threshold N             SSH TCP/22 connection threshold/window (default: 10).
  --port-threshold N            Unique destination-port threshold/window (default: 15).
  --host-threshold N            Unique destination-host threshold on same port (default: 15).
  --flood-window SEC            Connection flood window (default: 10).
  --flood-threshold N           Connections to same service/flood window (default: 100).
  --beacon-window SEC           Beacon observation window (default: 600).
  --beacon-min-connections N    Minimum periodic connections (default: 6).
  --beacon-min-interval SEC     Minimum mean beacon interval (default: 5).
  --beacon-max-interval SEC     Maximum mean beacon interval (default: 300).
  --beacon-max-cv FLOAT         Maximum interval coefficient of variation (default: 0.15).
  --behavior-cooldown SEC       Alert cooldown per behavior/key (default: 60).
  --ignore-service HOST:PORT    Exclude exact known service from ML + behavior alerts. Repeatable.
                                Elasticsearch from --es-host is ignored automatically.

Elasticsearch/Filebeat options:
  --es-host URL                 Elasticsearch URL (default: $ES_HOST).
  --es-user USER                Elasticsearch username (default: $ES_USER).
  --es-password-file FILE       Read Elasticsearch password from first line of FILE.
                                Otherwise prompt securely, or use ES_PASSWORD env var.
  --es-ca-cert FILE             Verify Elasticsearch TLS with this CA file.
  --es-insecure                 Disable TLS certificate verification (default).
  --elastic-major N             Elastic package major if Filebeat must be installed (default: 9).
  --ship-all-predictions        Also send detections.jsonl (NORMAL + BOTNET) to Elasticsearch.
  --skip-filebeat               Do not install/configure the dedicated Filebeat instance.

Examples:
  sudo ./install.sh --interface enp0s3
  sudo ./install.sh --interface enp0s3 --es-host https://10.70.128.26:9200
  sudo ES_PASSWORD='...' ./install.sh --interface enp0s3
  sudo ./install.sh --interface enp0s3 --es-password-file /root/es.pass
USAGE
}

log() { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
die() { log "ERROR: $*"; exit 1; }

backup_file() {
  local path="$1"
  [[ -e "$path" ]] || return 0
  cp -a "$path" "$path.bak.$TS"
  log "Backup: $path -> $path.bak.$TS"
}

add_ignore_service() {
  local service="$1" existing
  [[ -n "$service" ]] || return 0
  for existing in "${IGNORE_SERVICES[@]}"; do
    [[ "$existing" == "$service" ]] && return 0
  done
  IGNORE_SERVICES+=("$service")
}

prepare_ignore_services() {
  # Automatically suppress the exact Elasticsearch service used by this installer.
  # Only HOST:PORT is ignored; other traffic to/from the same host remains visible.
  local authority host port resolved
  authority="${ES_HOST#*://}"
  authority="${authority%%/*}"
  authority="${authority##*@}"
  host=""
  port="9200"

  if [[ "$authority" == \[*\]:* ]]; then
    host="${authority%%]*}"
    host="${host#[}"
    port="${authority##*:}"
  elif [[ "$authority" == *:* ]]; then
    host="${authority%:*}"
    port="${authority##*:}"
  else
    host="$authority"
  fi

  if [[ -n "$host" && "$port" =~ ^[0-9]+$ ]]; then
    if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      add_ignore_service "$host:$port"
    elif [[ "$host" == *:* ]]; then
      add_ignore_service "[$host]:$port"
    elif command -v getent >/dev/null 2>&1; then
      resolved="$(getent ahostsv4 "$host" 2>/dev/null | awk 'NR==1 {print $1}')"
      if [[ -n "$resolved" ]]; then
        add_ignore_service "$resolved:$port"
      else
        log "WARNING: could not resolve Elasticsearch host '$host' for detector suppression"
      fi
    fi
  fi

  if ((${#IGNORE_SERVICES[@]})); then
    log "Known services excluded from ML/behavior alerts: ${IGNORE_SERVICES[*]}"
  else
    log "Known-service exclusion list is empty"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --interface) [[ $# -ge 2 ]] || die "--interface requires a value"; INTERFACE="$2"; shift 2 ;;
    --skip-zeek-install) SKIP_ZEEK_INSTALL=1; shift ;;
    --behavior-window) [[ $# -ge 2 ]] || die "--behavior-window requires a value"; BEHAVIOR_WINDOW="$2"; shift 2 ;;
    --http-threshold) [[ $# -ge 2 ]] || die "--http-threshold requires a value"; HTTP_THRESHOLD="$2"; shift 2 ;;
    --ssh-threshold) [[ $# -ge 2 ]] || die "--ssh-threshold requires a value"; SSH_THRESHOLD="$2"; shift 2 ;;
    --port-threshold) [[ $# -ge 2 ]] || die "--port-threshold requires a value"; PORT_THRESHOLD="$2"; shift 2 ;;
    --host-threshold) [[ $# -ge 2 ]] || die "--host-threshold requires a value"; HOST_THRESHOLD="$2"; shift 2 ;;
    --flood-window) [[ $# -ge 2 ]] || die "--flood-window requires a value"; FLOOD_WINDOW="$2"; shift 2 ;;
    --flood-threshold) [[ $# -ge 2 ]] || die "--flood-threshold requires a value"; FLOOD_THRESHOLD="$2"; shift 2 ;;
    --beacon-window) [[ $# -ge 2 ]] || die "--beacon-window requires a value"; BEACON_WINDOW="$2"; shift 2 ;;
    --beacon-min-connections) [[ $# -ge 2 ]] || die "--beacon-min-connections requires a value"; BEACON_MIN_CONNECTIONS="$2"; shift 2 ;;
    --beacon-min-interval) [[ $# -ge 2 ]] || die "--beacon-min-interval requires a value"; BEACON_MIN_INTERVAL="$2"; shift 2 ;;
    --beacon-max-interval) [[ $# -ge 2 ]] || die "--beacon-max-interval requires a value"; BEACON_MAX_INTERVAL="$2"; shift 2 ;;
    --beacon-max-cv) [[ $# -ge 2 ]] || die "--beacon-max-cv requires a value"; BEACON_MAX_CV="$2"; shift 2 ;;
    --behavior-cooldown) [[ $# -ge 2 ]] || die "--behavior-cooldown requires a value"; BEHAVIOR_COOLDOWN="$2"; shift 2 ;;
    --ignore-service) [[ $# -ge 2 ]] || die "--ignore-service requires HOST:PORT"; IGNORE_SERVICES+=("$2"); shift 2 ;;
    --es-host) [[ $# -ge 2 ]] || die "--es-host requires a value"; ES_HOST="$2"; shift 2 ;;
    --es-user) [[ $# -ge 2 ]] || die "--es-user requires a value"; ES_USER="$2"; shift 2 ;;
    --es-password-file) [[ $# -ge 2 ]] || die "--es-password-file requires a value"; ES_PASSWORD_FILE="$2"; shift 2 ;;
    --es-ca-cert) [[ $# -ge 2 ]] || die "--es-ca-cert requires a value"; ES_CA_CERT="$2"; ES_INSECURE=0; shift 2 ;;
    --es-insecure) ES_INSECURE=1; shift ;;
    --elastic-major) [[ $# -ge 2 ]] || die "--elastic-major requires a value"; ELASTIC_MAJOR="$2"; shift 2 ;;
    --ship-all-predictions) SHIP_ALL_PREDICTIONS=1; shift ;;
    --skip-filebeat) SKIP_FILEBEAT=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done

[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Run as root: sudo ./install.sh ..."
for n in "$BEHAVIOR_WINDOW" "$HTTP_THRESHOLD" "$SSH_THRESHOLD" "$PORT_THRESHOLD" "$HOST_THRESHOLD" "$FLOOD_WINDOW" "$FLOOD_THRESHOLD" "$BEACON_WINDOW" "$BEACON_MIN_CONNECTIONS" "$BEHAVIOR_COOLDOWN"; do
  [[ "$n" =~ ^[1-9][0-9]*$ ]] || die "Behavior integer thresholds/windows must be positive integers"
done
awk -v v="$BEACON_MIN_INTERVAL" 'BEGIN { exit !(v > 0) }' || die "--beacon-min-interval must be > 0"
awk -v v="$BEACON_MAX_INTERVAL" 'BEGIN { exit !(v > 0) }' || die "--beacon-max-interval must be > 0"
awk -v a="$BEACON_MIN_INTERVAL" -v b="$BEACON_MAX_INTERVAL" 'BEGIN { exit !(a < b) }' || die "beacon minimum interval must be lower than maximum interval"
awk -v v="$BEACON_MAX_CV" 'BEGIN { exit !(v > 0 && v <= 1) }' || die "--beacon-max-cv must be > 0 and <= 1"
[[ "$ELASTIC_MAJOR" =~ ^[0-9]+$ ]] || die "--elastic-major must be numeric"

mkdir -p "$(dirname "$INSTALL_LOG")"
touch "$INSTALL_LOG"
exec > >(tee -a "$INSTALL_LOG") 2>&1

log "Zeek Botnet + Behavior installer v$VERSION"
log "Design: package-only Zeek + isolated Filebeat instance"

for f in "$MODEL_SRC" "$CONFIG_SRC" "$FEATURE_SRC" "$DETECTOR_SRC" "$BEHAVIOR_SRC" "$MONITOR_SRC"; do
  [[ -f "$f" ]] || die "Missing payload file: $f"
done
[[ $(stat -c '%s' "$MODEL_SRC") -gt 1024 ]] || die "Put rf_official_bro_final_pipeline.joblib into payload/models/"
[[ $(stat -c '%s' "$CONFIG_SRC") -gt 256 ]] || die "Put zeek_official_active_feature_config.pkl into payload/models/"

[[ -r /etc/os-release ]] || die "/etc/os-release not found"
# shellcheck disable=SC1091
source /etc/os-release
OS_ID="${ID:-unknown}"
OS_VERSION="${VERSION_ID:-unknown}"
OS_MAJOR="${OS_VERSION%%.*}"
OS_LIKE="${ID_LIKE:-}"
log "Detected OS: ${PRETTY_NAME:-$OS_ID $OS_VERSION}"

case "$OS_ID" in
  ubuntu|debian|almalinux|rocky|rhel|centos|fedora) ;;
  *)
    if [[ "$OS_LIKE" != *debian* && "$OS_LIKE" != *rhel* && "$OS_LIKE" != *fedora* ]]; then
      die "Unsupported distribution: $OS_ID"
    fi
    ;;
esac
if [[ "$OS_ID" == "centos" && "$OS_MAJOR" =~ ^[0-7]$ ]]; then
  die "CentOS 7 or older is not supported"
fi

if [[ -z "$INTERFACE" ]]; then
  INTERFACE="$(ip route show default 2>/dev/null | awk 'NR==1 {print $5}')"
  [[ -n "$INTERFACE" ]] || die "Cannot auto-detect interface; use --interface IFACE"
fi
ip link show "$INTERFACE" >/dev/null 2>&1 || die "Network interface not found: $INTERFACE"
log "Capture interface: $INTERFACE"

install_common_packages() {
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y curl wget ca-certificates gnupg gpg jq iproute2 acl util-linux
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y curl wget ca-certificates gnupg2 jq iproute acl util-linux dnf-plugins-core || \
      dnf install -y curl wget ca-certificates jq iproute acl util-linux dnf-plugins-core
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl wget ca-certificates jq iproute acl util-linux
  else
    die "No supported package manager found"
  fi
}

find_zeek_bin() {
  local p
  for p in "$(command -v zeek 2>/dev/null || true)" /opt/zeek/bin/zeek /usr/bin/zeek; do
    [[ -n "$p" && -x "$p" ]] && { readlink -f "$p"; return 0; }
  done
  return 1
}

find_zeekctl_bin() {
  local p
  for p in "$(command -v zeekctl 2>/dev/null || true)" /opt/zeek/bin/zeekctl /usr/bin/zeekctl; do
    [[ -n "$p" && -x "$p" ]] && { readlink -f "$p"; return 0; }
  done
  return 1
}

install_zeek_package_apt() {
  local repo_name=""
  case "$OS_ID:$OS_VERSION" in
    ubuntu:22.04) repo_name="xUbuntu_22.04" ;;
    ubuntu:24.04) repo_name="xUbuntu_24.04" ;;
    ubuntu:26.04) repo_name="xUbuntu_26.04" ;;
    debian:12) repo_name="Debian_12" ;;
    debian:13) repo_name="Debian_13" ;;
    *) die "No package-only Zeek repo mapping for $OS_ID $OS_VERSION. Install Zeek package manually then rerun with --skip-zeek-install." ;;
  esac
  log "Installing Zeek from security:zeek package repository ($repo_name); no source build"
  mkdir -p /etc/apt/keyrings
  curl -fsSL "https://download.opensuse.org/repositories/security:/zeek/$repo_name/Release.key" \
    | gpg --dearmor --yes -o /etc/apt/keyrings/security-zeek.gpg
  echo "deb [signed-by=/etc/apt/keyrings/security-zeek.gpg] https://download.opensuse.org/repositories/security:/zeek/$repo_name/ /" \
    > /etc/apt/sources.list.d/security-zeek.list
  apt-get update
  apt-get install -y zeek
}

install_zeek_package_rpm() {
  log "Installing Zeek from RPM repositories; no source build"
  if command -v dnf >/dev/null 2>&1; then
    dnf install -y epel-release || true
    dnf config-manager --set-enabled crb >/dev/null 2>&1 || true
    if ! dnf install -y zeek-core zeekctl zeek-zkg; then
      log "zeek-core/zeekctl packages unavailable; trying package name 'zeek'"
      dnf install -y zeek || die "Package-only Zeek installation failed. No source-build fallback will be used."
    fi
  else
    yum install -y epel-release || true
    if ! yum install -y zeek-core zeekctl zeek-zkg; then
      yum install -y zeek || die "Package-only Zeek installation failed. No source-build fallback will be used."
    fi
  fi
}

install_zeek_if_needed() {
  if find_zeek_bin >/dev/null 2>&1 && find_zeekctl_bin >/dev/null 2>&1; then
    log "Existing Zeek detected; package installation skipped"
    return
  fi
  [[ "$SKIP_ZEEK_INSTALL" -eq 0 ]] || die "Zeek not found and --skip-zeek-install supplied"
  if command -v apt-get >/dev/null 2>&1; then
    install_zeek_package_apt
  else
    install_zeek_package_rpm
  fi
}

resolve_zeek_layout() {
  ZEEK_BIN="$(find_zeek_bin || true)"
  ZEEKCTL="$(find_zeekctl_bin || true)"
  [[ -n "$ZEEK_BIN" && -n "$ZEEKCTL" ]] || die "Zeek/zeekctl still not found after package installation"

  if [[ -f /etc/zeek/node.cfg ]]; then
    NODE_CFG="/etc/zeek/node.cfg"
    SITE_DIR="/usr/share/zeek/site"
    LOCAL_ZEEK="$SITE_DIR/local.zeek"
    FALLBACK_LOG_ROOT="/var/log/zeek/logs"
    FALLBACK_SPOOL_ROOT="/var/log/zeek/spool"
  elif [[ -f /opt/zeek/etc/node.cfg ]]; then
    NODE_CFG="/opt/zeek/etc/node.cfg"
    SITE_DIR="/opt/zeek/share/zeek/site"
    LOCAL_ZEEK="$SITE_DIR/local.zeek"
    FALLBACK_LOG_ROOT="/opt/zeek/logs"
    FALLBACK_SPOOL_ROOT="/opt/zeek/spool"
  else
    die "Could not locate Zeek node.cfg (/etc/zeek or /opt/zeek/etc)"
  fi

  # Do not guess the ZeekControl log layout. Package builds differ between
  # Ubuntu/Debian and EPEL/RHEL-family systems. In particular, AlmaLinux EPEL
  # commonly reports logdir=/var/log/zeek/logs and spooldir=/var/log/zeek/spool.
  # The live logs are then available through logdir/current -> spooldir/zeek.
  local zc_config
  zc_config="$($ZEEKCTL config 2>/dev/null || true)"
  ZEEK_LOG_ROOT="$(printf '%s\n' "$zc_config" | awk -F'[[:space:]]*=[[:space:]]*' '$1 ~ /^[[:space:]]*logdir[[:space:]]*$/ {print $2; exit}')"
  ZEEK_SPOOL_ROOT="$(printf '%s\n' "$zc_config" | awk -F'[[:space:]]*=[[:space:]]*' '$1 ~ /^[[:space:]]*spooldir[[:space:]]*$/ {print $2; exit}')"
  ZEEK_LOG_ROOT="${ZEEK_LOG_ROOT:-$FALLBACK_LOG_ROOT}"
  ZEEK_SPOOL_ROOT="${ZEEK_SPOOL_ROOT:-$FALLBACK_SPOOL_ROOT}"

  CONN_LOG="$ZEEK_LOG_ROOT/current/conn.log"
  HTTP_LOG="$ZEEK_LOG_ROOT/current/http.log"
  log "Zeek: $($ZEEK_BIN --version 2>&1 | head -1)"
  log "node.cfg: $NODE_CFG"
  log "local.zeek: $LOCAL_ZEEK"
  log "ZeekControl logdir: $ZEEK_LOG_ROOT"
  log "ZeekControl spooldir: $ZEEK_SPOOL_ROOT"
  log "Live conn.log: $CONN_LOG"
  log "Live http.log: $HTTP_LOG"
}

configure_zeek_non_destructive() {
  mkdir -p "$SITE_DIR"
  touch "$LOCAL_ZEEK"
  backup_file "$NODE_CFG"
  backup_file "$LOCAL_ZEEK"

  local if_count
  if_count="$(grep -Ec '^[[:space:]]*interface[[:space:]]*=' "$NODE_CFG" || true)"
  if [[ "$if_count" -gt 1 ]]; then
    die "node.cfg contains multiple interface= entries. Refusing to rewrite a possible cluster config. Configure $INTERFACE manually and rerun."
  elif [[ "$if_count" -eq 1 ]]; then
    sed -i -E "s|^[[:space:]]*interface[[:space:]]*=.*|interface=$INTERFACE|" "$NODE_CFG"
  else
    if grep -q '^\[zeek\]' "$NODE_CFG"; then
      sed -i "/^\[zeek\]/a interface=$INTERFACE" "$NODE_CFG"
    else
      die "No interface= and no [zeek] standalone section found in node.cfg. Refusing destructive replacement."
    fi
  fi

  MANAGED_ZEEK="$SITE_DIR/zeek-botnet-detector.zeek"
  backup_file "$MANAGED_ZEEK"
  {
    echo '# Managed by zeek-botnet-installer; safe to remove with uninstall.sh'
    if ! grep -RqsE '^[[:space:]]*@load[[:space:]]+base/protocols/http' "$LOCAL_ZEEK" "$SITE_DIR"/*.zeek 2>/dev/null; then
      echo '@load base/protocols/http'
    else
      echo '# HTTP analyzer already loaded elsewhere.'
    fi
    if ! grep -RqsE '^[[:space:]]*redef[[:space:]]+LogAscii::use_json[[:space:]]*=[[:space:]]*T[[:space:]]*;' "$LOCAL_ZEEK" "$SITE_DIR"/*.zeek 2>/dev/null; then
      echo 'redef LogAscii::use_json = T;'
    else
      echo '# JSON logging already enabled elsewhere.'
    fi
  } > "$MANAGED_ZEEK"

  if ! grep -qE '^[[:space:]]*@load[[:space:]]+zeek-botnet-detector[[:space:]]*$' "$LOCAL_ZEEK"; then
    cat >> "$LOCAL_ZEEK" <<'EOF_LOCAL'

# BEGIN zeek-botnet-installer managed load
@load zeek-botnet-detector
# END zeek-botnet-installer managed load
EOF_LOCAL
  fi

  "$ZEEKCTL" check
  log "Deploying/reloading Zeek configuration via zeekctl"
  "$ZEEKCTL" deploy
}

setup_zeek_autostart_without_collision() {
  # Do not overwrite any existing zeek.service.
  if systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | grep -qx 'zeek.service'; then
    systemctl enable zeek.service >/dev/null 2>&1 || true
    log "Existing zeek.service found; left untouched"
    return
  fi
  if systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | grep -qx 'zeekctl.service'; then
    systemctl enable zeekctl.service >/dev/null 2>&1 || true
    log "Existing zeekctl.service found; left untouched"
    return
  fi

  local unit="/etc/systemd/system/zeek-botnet-zeekctl.service"
  backup_file "$unit"
  cat > "$unit" <<EOF_UNIT
[Unit]
Description=ZeekControl startup for Zeek Botnet Sensor
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$ZEEKCTL start
ExecStop=$ZEEKCTL stop
ExecReload=$ZEEKCTL deploy
TimeoutStartSec=120
TimeoutStopSec=120

[Install]
WantedBy=multi-user.target
EOF_UNIT
  systemctl enable zeek-botnet-zeekctl.service >/dev/null
  log "Created dedicated zeek-botnet-zeekctl.service because no existing Zeek service was present"
}

setup_detector_user_and_acl() {
  getent group "$DETECTOR_GROUP" >/dev/null 2>&1 || groupadd --system "$DETECTOR_GROUP"
  if ! id "$DETECTOR_USER" >/dev/null 2>&1; then
    useradd --system --create-home --home-dir "/var/lib/$DETECTOR_USER" --shell /usr/sbin/nologin --gid "$DETECTOR_GROUP" "$DETECTOR_USER"
  fi
  mkdir -p "$ZEEK_LOG_ROOT" "$ZEEK_SPOOL_ROOT"
  # ACL adds read/traverse access without changing existing owner/group/mode.
  setfacl -Rm "u:$DETECTOR_USER:rX" "$ZEEK_LOG_ROOT" "$ZEEK_SPOOL_ROOT" || true
  setfacl -Rm "d:u:$DETECTOR_USER:rX" "$ZEEK_LOG_ROOT" "$ZEEK_SPOOL_ROOT" || true
}

install_detector_payload() {
  install -d -m 0750 -o "$DETECTOR_USER" -g "$DETECTOR_GROUP" "$INSTALL_DIR" "$INSTALL_DIR/src" "$INSTALL_DIR/models" "$INSTALL_DIR/logs"
  local deployed
  for deployed in \
    "$INSTALL_DIR/src/feature_engineering.py" \
    "$INSTALL_DIR/src/detector.py" \
    "$INSTALL_DIR/src/behavior_detector.py" \
    "$INSTALL_DIR/src/monitor.sh" \
    "$INSTALL_DIR/models/rf_official_bro_final_pipeline.joblib" \
    "$INSTALL_DIR/models/zeek_official_active_feature_config.pkl"; do
    backup_file "$deployed"
  done
  install -m 0640 -o root -g "$DETECTOR_GROUP" "$FEATURE_SRC" "$INSTALL_DIR/src/feature_engineering.py"
  install -m 0640 -o root -g "$DETECTOR_GROUP" "$DETECTOR_SRC" "$INSTALL_DIR/src/detector.py"
  install -m 0640 -o root -g "$DETECTOR_GROUP" "$BEHAVIOR_SRC" "$INSTALL_DIR/src/behavior_detector.py"
  install -m 0750 -o root -g "$DETECTOR_GROUP" "$MONITOR_SRC" "$INSTALL_DIR/src/monitor.sh"
  install -m 0640 -o root -g "$DETECTOR_GROUP" "$MODEL_SRC" "$INSTALL_DIR/models/rf_official_bro_final_pipeline.joblib"
  install -m 0640 -o root -g "$DETECTOR_GROUP" "$CONFIG_SRC" "$INSTALL_DIR/models/zeek_official_active_feature_config.pkl"
  chown "$DETECTOR_USER:$DETECTOR_GROUP" "$INSTALL_DIR/logs"
}

setup_python_runtime() {
  if ! command -v uv >/dev/null 2>&1; then
    log "Installing uv (Python runtime manager)"
    local tmp_uv
    tmp_uv="$(mktemp -d)"
    HOME="$tmp_uv" sh -c 'curl -LsSf https://astral.sh/uv/install.sh | sh'
    [[ -x "$tmp_uv/.local/bin/uv" ]] || die "uv installation failed"
    install -m 0755 "$tmp_uv/.local/bin/uv" /usr/local/bin/uv
    rm -rf "$tmp_uv"
  fi

  local detector_home="/var/lib/$DETECTOR_USER"
  install -d -m 0700 -o "$DETECTOR_USER" -g "$DETECTOR_GROUP" "$detector_home"

  # Run uv from the detector user's own home. This makes the installer safe even
  # when the bundle itself lives under a private /home/<admin> directory that
  # zeekbot cannot traverse. It also prevents uv from trying to inspect a
  # project-level uv.toml in the installer's current working directory.
  (
    cd "$detector_home"
    runuser -u "$DETECTOR_USER" -- env HOME="$detector_home" /usr/local/bin/uv python install "$PYTHON_VERSION"
  )

  if [[ -d "$INSTALL_DIR/venv" ]]; then
    mv "$INSTALL_DIR/venv" "$INSTALL_DIR/venv.bak.$TS"
  fi
  (
    cd "$detector_home"
    runuser -u "$DETECTOR_USER" -- env HOME="$detector_home" /usr/local/bin/uv venv --python "$PYTHON_VERSION" "$INSTALL_DIR/venv"
    runuser -u "$DETECTOR_USER" -- env HOME="$detector_home" /usr/local/bin/uv pip install \
      --python "$INSTALL_DIR/venv/bin/python" \
      numpy==2.5.3 pandas==3.0.6 scikit-learn==1.9.1 joblib==1.6.0 pip
  )

  # On SELinux-enforcing RHEL-family systems, uv's managed Python is stored under
  # /var/lib/zeekbot and normally inherits var_lib_t. systemd/init_t cannot execute
  # that label, causing status=203/EXEC. Persistently label ONLY uv's Python runtime
  # tree executable-safe; do not disable SELinux and do not relabel all of /var/lib.
  if command -v getenforce >/dev/null 2>&1 && [[ "$(getenforce 2>/dev/null || true)" != "Disabled" ]]; then
    if command -v dnf >/dev/null 2>&1; then
      dnf install -y policycoreutils-python-utils >/dev/null 2>&1 || true
    elif command -v yum >/dev/null 2>&1; then
      yum install -y policycoreutils-python-utils >/dev/null 2>&1 || true
    fi
    local uv_python_root="$detector_home/.local/share/uv/python"
    if [[ -d "$uv_python_root" ]] && command -v semanage >/dev/null 2>&1; then
      semanage fcontext -a -t bin_t "$uv_python_root(/.*)?" 2>/dev/null || \
        semanage fcontext -m -t bin_t "$uv_python_root(/.*)?"
      restorecon -RF "$uv_python_root"
      log "SELinux context applied to uv Python runtime: $uv_python_root -> bin_t"
    elif [[ -d "$uv_python_root" ]]; then
      log "WARNING: SELinux is enabled but semanage is unavailable; detector service may hit 203/EXEC"
    fi
  fi

  "$INSTALL_DIR/venv/bin/python" -m py_compile \
    "$INSTALL_DIR/src/feature_engineering.py" \
    "$INSTALL_DIR/src/detector.py" \
    "$INSTALL_DIR/src/behavior_detector.py"

  "$INSTALL_DIR/venv/bin/python" - <<'PY_CHECK'
from pathlib import Path
import joblib
base = Path('/opt/zeek-botnet-detector/models')
model = joblib.load(base / 'rf_official_bro_final_pipeline.joblib')
config = joblib.load(base / 'zeek_official_active_feature_config.pkl')
active = config['active_feature_columns']
encoded = model.named_steps['preprocessor'].get_feature_names_out()
assert len(active) == 40, f'Expected 40 active features, got {len(active)}'
assert len(encoded) == 433, f'Expected 433 encoded features, got {len(encoded)}'
print(f'Model contract OK: {len(active)} raw -> {len(encoded)} encoded features')
PY_CHECK
}

setup_detector_services() {
  local ignore_args="" service
  for service in "${IGNORE_SERVICES[@]}"; do
    ignore_args+=" --ignore-service $service"
  done

  backup_file /etc/systemd/system/zeek-botnet-detector.service
  cat > /etc/systemd/system/zeek-botnet-detector.service <<EOF_ML
[Unit]
Description=Zeek Random Forest Botnet Detector (Shadow Mode)
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=$DETECTOR_USER
Group=$DETECTOR_GROUP
WorkingDirectory=$INSTALL_DIR/src
Environment=PYTHONUNBUFFERED=1
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/src/detector.py --conn-log $CONN_LOG$ignore_args
Restart=always
RestartSec=3
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF_ML

  backup_file /etc/systemd/system/zeek-behavior-detector.service
  cat > /etc/systemd/system/zeek-behavior-detector.service <<EOF_BEHAVIOR
[Unit]
Description=Zeek Multi-Behavior Security Detector (Shadow Mode)
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=$DETECTOR_USER
Group=$DETECTOR_GROUP
WorkingDirectory=$INSTALL_DIR/src
Environment=PYTHONUNBUFFERED=1
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/src/behavior_detector.py --http-log $HTTP_LOG --conn-log $CONN_LOG --alert-log $INSTALL_DIR/logs/behavior_alerts.jsonl --window $BEHAVIOR_WINDOW --http-threshold $HTTP_THRESHOLD --ssh-threshold $SSH_THRESHOLD --port-threshold $PORT_THRESHOLD --host-threshold $HOST_THRESHOLD --flood-window $FLOOD_WINDOW --flood-threshold $FLOOD_THRESHOLD --beacon-window $BEACON_WINDOW --beacon-min-connections $BEACON_MIN_CONNECTIONS --beacon-min-interval $BEACON_MIN_INTERVAL --beacon-max-interval $BEACON_MAX_INTERVAL --beacon-max-cv $BEACON_MAX_CV --cooldown $BEHAVIOR_COOLDOWN$ignore_args
Restart=always
RestartSec=3
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF_BEHAVIOR
}

install_filebeat_package_if_needed() {
  command -v filebeat >/dev/null 2>&1 && { log "Existing Filebeat binary detected; package installation skipped"; return; }
  log "Installing Filebeat package only; existing Filebeat config is not created/overwritten by this step"
  if command -v apt-get >/dev/null 2>&1; then
    mkdir -p /usr/share/keyrings
    curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor --yes -o /usr/share/keyrings/elastic-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/elastic-keyring.gpg] https://artifacts.elastic.co/packages/${ELASTIC_MAJOR}.x/apt stable main" \
      > "/etc/apt/sources.list.d/elastic-${ELASTIC_MAJOR}.x.list"
    apt-get update
    apt-get install -y filebeat
  else
    rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch
    cat > "/etc/yum.repos.d/elastic-${ELASTIC_MAJOR}.x.repo" <<EOF_REPO
[elastic-${ELASTIC_MAJOR}.x]
name=Elastic repository for ${ELASTIC_MAJOR}.x packages
baseurl=https://artifacts.elastic.co/packages/${ELASTIC_MAJOR}.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF_REPO
    if command -v dnf >/dev/null 2>&1; then dnf install -y filebeat; else yum install -y filebeat; fi
  fi
}

read_es_password() {
  [[ "$SKIP_FILEBEAT" -eq 0 ]] || return 0
  if [[ -n "$ES_PASSWORD_FILE" ]]; then
    [[ -r "$ES_PASSWORD_FILE" ]] || die "Cannot read --es-password-file: $ES_PASSWORD_FILE"
    IFS= read -r ES_PASSWORD < "$ES_PASSWORD_FILE"
  fi
  if [[ -z "$ES_PASSWORD" ]]; then
    if [[ -t 0 ]]; then
      read -r -s -p "Elasticsearch password for $ES_USER: " ES_PASSWORD
      echo
    else
      die "No Elasticsearch password. Set ES_PASSWORD or use --es-password-file in non-interactive mode."
    fi
  fi
  [[ -n "$ES_PASSWORD" ]] || die "Elasticsearch password is empty"
}

yaml_quote() {
  # Single-quoted YAML string, escaping embedded single quotes.
  printf "'%s'" "${1//\'/\'\'}"
}

setup_isolated_filebeat() {
  [[ "$SKIP_FILEBEAT" -eq 0 ]] || { log "Dedicated Filebeat skipped"; return; }
  install_filebeat_package_if_needed
  local fb_bin
  fb_bin="$(command -v filebeat || true)"
  [[ -x "$fb_bin" ]] || die "Filebeat binary not found after installation"

  # Safety guarantee: do not touch default config/service.
  log "Existing /etc/filebeat/filebeat.yml and filebeat.service will NOT be modified or restarted"
  mkdir -p "$FILEBEAT_CONFIG_DIR" "$FILEBEAT_DATA" "$FILEBEAT_LOGS"
  chmod 0700 "$FILEBEAT_CONFIG_DIR"
  backup_file "$FILEBEAT_CONFIG"
  backup_file "$FILEBEAT_SERVICE"
  backup_file "$FILEBEAT_KEYSTORE"

  if [[ -n "$ES_CA_CERT" ]]; then
    [[ -r "$ES_CA_CERT" ]] || die "CA file not readable: $ES_CA_CERT"
    install -m 0644 "$ES_CA_CERT" "$FILEBEAT_CONFIG_DIR/elasticsearch-ca.crt"
  fi

  cat > "$FILEBEAT_CONFIG" <<EOF_FB
# Dedicated Filebeat instance for Zeek Botnet Detector.
# This file is intentionally separate from /etc/filebeat/filebeat.yml.
# Use an explicit keystore path so this instance never falls back to
# the default /var/lib/filebeat/filebeat.keystore.
keystore.path: "$FILEBEAT_KEYSTORE"

filebeat.inputs:
  - type: filestream
    id: zeek-botnet-ml-alerts-v1
    enabled: true
    paths:
      - $INSTALL_DIR/logs/botnet_alerts.jsonl
    parsers:
      - ndjson:
          target: ""
          add_error_key: true
    fields:
      log_type: zeek_botnet_ml_alert
      event_dataset: capstone.zeek_botnet
    fields_under_root: true

  - type: filestream
    id: zeek-botnet-behavior-alerts-v1
    enabled: true
    paths:
      - $INSTALL_DIR/logs/behavior_alerts.jsonl
    parsers:
      - ndjson:
          target: ""
          add_error_key: true
    fields:
      log_type: zeek_behavior_alert
      event_dataset: capstone.zeek_behavior
    fields_under_root: true
EOF_FB

  if [[ "$SHIP_ALL_PREDICTIONS" -eq 1 ]]; then
    cat >> "$FILEBEAT_CONFIG" <<EOF_FB_ALL

  - type: filestream
    id: zeek-botnet-all-predictions-v1
    enabled: true
    paths:
      - $INSTALL_DIR/logs/detections.jsonl
    parsers:
      - ndjson:
          target: ""
          add_error_key: true
    fields:
      log_type: zeek_botnet_prediction
      event_dataset: capstone.zeek_botnet_prediction
    fields_under_root: true
EOF_FB_ALL
  fi

  cat >> "$FILEBEAT_CONFIG" <<EOF_FB2

processors:
  - add_host_metadata: ~

setup.ilm.enabled: false
setup.template.enabled: false

output.elasticsearch:
  hosts: [$(yaml_quote "$ES_HOST")]
  username: $(yaml_quote "$ES_USER")
  password: "\${ES_PASSWORD}"
  indices:
    - index: "capstone-zeek-botnet-alerts-%{+yyyy.MM.dd}"
      when.equals:
        log_type: "zeek_botnet_ml_alert"
    - index: "capstone-zeek-behavior-alerts-%{+yyyy.MM.dd}"
      when.equals:
        log_type: "zeek_behavior_alert"
EOF_FB2

  if [[ "$SHIP_ALL_PREDICTIONS" -eq 1 ]]; then
    cat >> "$FILEBEAT_CONFIG" <<'EOF_FB3'
    - index: "capstone-zeek-botnet-predictions-%{+yyyy.MM.dd}"
      when.equals:
        log_type: "zeek_botnet_prediction"
EOF_FB3
  fi

  if [[ -n "$ES_CA_CERT" ]]; then
    cat >> "$FILEBEAT_CONFIG" <<EOF_TLS
  ssl.certificate_authorities: ["$FILEBEAT_CONFIG_DIR/elasticsearch-ca.crt"]
  ssl.verification_mode: full
EOF_TLS
  elif [[ "$ES_INSECURE" -eq 1 ]]; then
    cat >> "$FILEBEAT_CONFIG" <<'EOF_TLS_INSECURE'
  ssl.verification_mode: none
EOF_TLS_INSECURE
    log "WARNING: Filebeat Elasticsearch TLS verification is disabled. Prefer --es-ca-cert in production."
  fi

  cat >> "$FILEBEAT_CONFIG" <<EOF_PATHS

path.data: "$FILEBEAT_DATA"
path.logs: "$FILEBEAT_LOGS"
logging.level: info
EOF_PATHS
  chmod 0600 "$FILEBEAT_CONFIG"

  local fb_home="/usr/share/filebeat"
  [[ -d "$fb_home" ]] || fb_home="/usr/share"

  # Keep the Elasticsearch password out of YAML. Filebeat package installs can
  # otherwise fall back to /var/lib/filebeat/filebeat.keystore even when a custom
  # path.data is supplied. Pin keystore.path explicitly for this dedicated instance.
  rm -f "$FILEBEAT_KEYSTORE"
  "$fb_bin" keystore create --force \
    -E "keystore.path=$FILEBEAT_KEYSTORE" \
    --path.home "$fb_home" --path.config "$FILEBEAT_CONFIG_DIR" \
    --path.data "$FILEBEAT_DATA" --path.logs "$FILEBEAT_LOGS" >/dev/null
  printf '%s' "$ES_PASSWORD" | "$fb_bin" keystore add ES_PASSWORD --stdin --force \
    -E "keystore.path=$FILEBEAT_KEYSTORE" \
    --path.home "$fb_home" --path.config "$FILEBEAT_CONFIG_DIR" \
    --path.data "$FILEBEAT_DATA" --path.logs "$FILEBEAT_LOGS" >/dev/null
  [[ -f "$FILEBEAT_KEYSTORE" ]] || die "Dedicated Filebeat keystore was not created at $FILEBEAT_KEYSTORE"
  chmod 0600 "$FILEBEAT_KEYSTORE"
  chown root:root "$FILEBEAT_KEYSTORE"
  if ! "$fb_bin" keystore list \
      -E "keystore.path=$FILEBEAT_KEYSTORE" \
      --path.home "$fb_home" --path.config "$FILEBEAT_CONFIG_DIR" \
      --path.data "$FILEBEAT_DATA" --path.logs "$FILEBEAT_LOGS" | grep -qx 'ES_PASSWORD'; then
    die "ES_PASSWORD was not written to the dedicated Filebeat keystore"
  fi
  chmod 0700 "$FILEBEAT_DATA"

  cat > "$FILEBEAT_SERVICE" <<EOF_FBSVC
[Unit]
Description=Dedicated Filebeat for Zeek Botnet Detector
Wants=network-online.target
After=network-online.target zeek-botnet-detector.service zeek-behavior-detector.service

[Service]
Type=simple
ExecStart=$fb_bin -e -c filebeat.yml -E keystore.path=$FILEBEAT_KEYSTORE --path.home $fb_home --path.config $FILEBEAT_CONFIG_DIR --path.data $FILEBEAT_DATA --path.logs $FILEBEAT_LOGS
Restart=always
RestartSec=5
UMask=0027

[Install]
WantedBy=multi-user.target
EOF_FBSVC

  "$fb_bin" test config -c filebeat.yml -E "keystore.path=$FILEBEAT_KEYSTORE" --path.home "$fb_home" --path.config "$FILEBEAT_CONFIG_DIR" --path.data "$FILEBEAT_DATA" --path.logs "$FILEBEAT_LOGS"
  if ! "$fb_bin" test output -c filebeat.yml -E "keystore.path=$FILEBEAT_KEYSTORE" --path.home "$fb_home" --path.config "$FILEBEAT_CONFIG_DIR" --path.data "$FILEBEAT_DATA" --path.logs "$FILEBEAT_LOGS"; then
    log "WARNING: Filebeat config is valid but Elasticsearch connectivity test failed. Service will still be installed for later recovery."
  fi
}

# Stop only services owned by this installer before an in-place upgrade.
# Existing default Zeek/Filebeat services are not touched here.
for _svc in filebeat-botnet.service zeek-behavior-detector.service zeek-botnet-detector.service; do
  systemctl stop "$_svc" >/dev/null 2>&1 || true
done

install_common_packages
prepare_ignore_services
install_zeek_if_needed
resolve_zeek_layout
configure_zeek_non_destructive
setup_zeek_autostart_without_collision
setup_detector_user_and_acl
install_detector_payload
setup_python_runtime
setup_detector_services
read_es_password
setup_isolated_filebeat

cat > "$RUNTIME_CONF" <<EOF_RUNTIME
# Generated by zeek-botnet-installer v$VERSION
INSTALL_DIR='$INSTALL_DIR'
ZEEK_BIN='$ZEEK_BIN'
ZEEKCTL='$ZEEKCTL'
NODE_CFG='$NODE_CFG'
LOCAL_ZEEK='$LOCAL_ZEEK'
ZEEK_LOG_ROOT='$ZEEK_LOG_ROOT'
CONN_LOG='$CONN_LOG'
HTTP_LOG='$HTTP_LOG'
INTERFACE='$INTERFACE'
BEHAVIOR_WINDOW='$BEHAVIOR_WINDOW'
HTTP_THRESHOLD='$HTTP_THRESHOLD'
SSH_THRESHOLD='$SSH_THRESHOLD'
PORT_THRESHOLD='$PORT_THRESHOLD'
HOST_THRESHOLD='$HOST_THRESHOLD'
FLOOD_WINDOW='$FLOOD_WINDOW'
FLOOD_THRESHOLD='$FLOOD_THRESHOLD'
BEACON_WINDOW='$BEACON_WINDOW'
BEACON_MIN_CONNECTIONS='$BEACON_MIN_CONNECTIONS'
BEACON_MIN_INTERVAL='$BEACON_MIN_INTERVAL'
BEACON_MAX_INTERVAL='$BEACON_MAX_INTERVAL'
BEACON_MAX_CV='$BEACON_MAX_CV'
BEHAVIOR_COOLDOWN='$BEHAVIOR_COOLDOWN'
IGNORE_SERVICES='${IGNORE_SERVICES[*]}'
FILEBEAT_CONFIG='$FILEBEAT_CONFIG'
FILEBEAT_KEYSTORE='$FILEBEAT_KEYSTORE'
ES_HOST='$ES_HOST'
SHIP_ALL_PREDICTIONS='$SHIP_ALL_PREDICTIONS'
EOF_RUNTIME
chmod 0644 "$RUNTIME_CONF"

systemctl daemon-reload
systemctl enable zeek-botnet-detector.service zeek-behavior-detector.service >/dev/null
systemctl restart zeek-botnet-detector.service zeek-behavior-detector.service
if [[ "$SKIP_FILEBEAT" -eq 0 ]]; then
  systemctl enable filebeat-botnet.service >/dev/null
  systemctl restart filebeat-botnet.service
fi
sleep 2
if [[ "$SKIP_FILEBEAT" -eq 0 ]] && ! systemctl is-active --quiet filebeat-botnet.service; then
  journalctl -u filebeat-botnet.service -n 30 --no-pager || true
  die "Dedicated Filebeat failed to stay active. Check the journal output above."
fi

log "Installation complete"
log "Zeek config was preserved except the single interface= value and one managed @load line; backups were created."
log "Default Filebeat config/service untouched: /etc/filebeat/filebeat.yml and filebeat.service"
log "ML detector: $(systemctl is-active zeek-botnet-detector.service || true)"
log "Behavior detector: $(systemctl is-active zeek-behavior-detector.service || true)"
if [[ "$SKIP_FILEBEAT" -eq 0 ]]; then
  log "Dedicated Filebeat: $(systemctl is-active filebeat-botnet.service || true)"
fi
log "conn.log: $CONN_LOG"
log "http.log: $HTTP_LOG"
log "ML alerts: $INSTALL_DIR/logs/botnet_alerts.jsonl"
log "Behavior alerts: $INSTALL_DIR/logs/behavior_alerts.jsonl"
log "Known services excluded from detector alerts: ${IGNORE_SERVICES[*]:-none}"
log "Behavior types: HTTP_BRUTE_FORCE SSH_BRUTE_FORCE PORT_SCAN HOST_SCAN CONNECTION_FLOOD BEACONING"
log "Elasticsearch indices: capstone-zeek-botnet-alerts-* and capstone-zeek-behavior-alerts-*"
log "Kibana combined Data View pattern: filebeat-*,capstone-zeek-*"
log "Run: sudo ./verify.sh"
