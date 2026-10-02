#!/usr/bin/env bash
set -u
CONF="/etc/zeek-botnet-detector.conf"
INSTALL_DIR="/opt/zeek-botnet-detector"

ok() { printf '[OK] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*"; FAILURES=$((FAILURES+1)); }
FAILURES=0

if [[ -r "$CONF" ]]; then
  # shellcheck disable=SC1090
  source "$CONF"
else
  fail "$CONF not found"
  ZEEK_BIN="$(command -v zeek 2>/dev/null || true)"
  ZEEKCTL="$(command -v zeekctl 2>/dev/null || true)"
  CONN_LOG=""
  HTTP_LOG=""
  FILEBEAT_CONFIG="/etc/filebeat-botnet/filebeat.yml"
  FILEBEAT_KEYSTORE="/etc/filebeat-botnet/filebeat.keystore"
fi

echo "============================================================"
echo " Zeek Botnet Detector v1.3.1 verification"
echo "============================================================"

if [[ -n "${ZEEK_BIN:-}" && -x "${ZEEK_BIN:-}" ]]; then
  ok "$($ZEEK_BIN --version 2>&1 | head -1)"
else
  fail "Zeek binary not found"
fi

if [[ -n "${ZEEKCTL:-}" && -x "${ZEEKCTL:-}" ]]; then
  echo "--- zeekctl status ---"
  "$ZEEKCTL" status || fail "zeekctl status failed"
else
  fail "zeekctl not found"
fi

for svc in zeek-botnet-detector.service zeek-behavior-detector.service; do
  if systemctl is-active --quiet "$svc"; then ok "$svc active"; else fail "$svc not active"; fi
done

if [[ -n "${IGNORE_SERVICES:-}" ]]; then
  ok "Known-service suppression configured: $IGNORE_SERVICES"
else
  warn "No known-service suppression listed in runtime config"
fi

if systemctl cat zeek-botnet-detector.service 2>/dev/null | grep -q -- '--ignore-service'; then
  ok "ML service has known-service exclusion arguments"
else
  warn "ML service has no --ignore-service argument"
fi
if systemctl cat zeek-behavior-detector.service 2>/dev/null | grep -q -- '--ignore-service'; then
  ok "Behavior service has known-service exclusion arguments"
else
  warn "Behavior service has no --ignore-service argument"
fi

BEHAVIOR_SRC="$INSTALL_DIR/src/behavior_detector.py"
if [[ -f "$BEHAVIOR_SRC" ]]; then
  missing_types=0
  for t in HTTP_BRUTE_FORCE SSH_BRUTE_FORCE PORT_SCAN HOST_SCAN CONNECTION_FLOOD BEACONING; do
    if ! grep -q "\"$t\"" "$BEHAVIOR_SRC"; then
      fail "Behavior type missing from deployed detector: $t"
      missing_types=1
    fi
  done
  [[ "$missing_types" -eq 0 ]] && ok "All 6 behavior types present"
fi

if command -v getenforce >/dev/null 2>&1 && [[ "$(getenforce 2>/dev/null || true)" != "Disabled" ]]; then
  PY_REAL="$(readlink -f "$INSTALL_DIR/venv/bin/python" 2>/dev/null || true)"
  if [[ -n "$PY_REAL" ]] && command -v ls >/dev/null 2>&1; then
    PY_CTX="$(ls -Zd "$PY_REAL" 2>/dev/null | awk '{print $1}' || true)"
    if systemctl is-active --quiet zeek-botnet-detector.service; then
      ok "SELinux/runtime execution OK (${PY_CTX:-context unknown})"
    elif [[ "$PY_CTX" == *var_lib_t* ]]; then
      fail "SELinux Python context is still var_lib_t: $PY_REAL"
    else
      warn "SELinux Python context: ${PY_CTX:-unknown}"
    fi
  fi
fi

if systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | grep -qx 'filebeat-botnet.service'; then
  if systemctl is-active --quiet filebeat-botnet.service; then ok "filebeat-botnet.service active"; else fail "filebeat-botnet.service not active"; fi
else
  warn "filebeat-botnet.service not installed (possibly --skip-filebeat)"
fi

FB_KEYSTORE="${FILEBEAT_KEYSTORE:-/etc/filebeat-botnet/filebeat.keystore}"
if [[ -f "$FB_KEYSTORE" ]]; then
  ok "Dedicated Filebeat keystore: $FB_KEYSTORE"
  if filebeat keystore list -E "keystore.path=$FB_KEYSTORE" --path.home /usr/share/filebeat --path.config /etc/filebeat-botnet --path.data /var/lib/filebeat-botnet --path.logs /var/log/filebeat-botnet 2>/dev/null | grep -qx 'ES_PASSWORD'; then
    ok "Dedicated Filebeat keystore contains ES_PASSWORD"
  else
    fail "ES_PASSWORD missing from dedicated Filebeat keystore"
  fi
else
  fail "Dedicated Filebeat keystore missing: $FB_KEYSTORE"
fi

if systemctl cat filebeat-botnet.service 2>/dev/null | grep -q -- "keystore.path=$FB_KEYSTORE"; then
  ok "filebeat-botnet.service pins dedicated keystore path"
else
  fail "filebeat-botnet.service does not pin the dedicated keystore path"
fi

[[ -n "${CONN_LOG:-}" && -e "$CONN_LOG" ]] && ok "conn.log: $CONN_LOG" || warn "conn.log not present yet: ${CONN_LOG:-unknown}"
[[ -n "${HTTP_LOG:-}" && -e "$HTTP_LOG" ]] && ok "http.log: $HTTP_LOG" || warn "http.log not present yet; it appears after HTTP traffic"

if [[ -x "$INSTALL_DIR/venv/bin/python" ]]; then
  "$INSTALL_DIR/venv/bin/python" - <<'PY' && ok "Model contract 40 -> 433 verified" || fail "Model contract verification failed"
from pathlib import Path
import joblib
base = Path('/opt/zeek-botnet-detector/models')
model = joblib.load(base / 'rf_official_bro_final_pipeline.joblib')
config = joblib.load(base / 'zeek_official_active_feature_config.pkl')
assert len(config['active_feature_columns']) == 40
assert len(model.named_steps['preprocessor'].get_feature_names_out()) == 433
print(type(model).__name__)
PY
else
  fail "Detector Python environment missing"
fi

if command -v filebeat >/dev/null 2>&1 && [[ -f "${FILEBEAT_CONFIG:-/etc/filebeat-botnet/filebeat.yml}" ]]; then
  FB_CONFIG="${FILEBEAT_CONFIG:-/etc/filebeat-botnet/filebeat.yml}"
  if filebeat test config -c filebeat.yml -E "keystore.path=$FB_KEYSTORE" --path.home /usr/share/filebeat --path.config /etc/filebeat-botnet --path.data /var/lib/filebeat-botnet --path.logs /var/log/filebeat-botnet >/dev/null 2>&1; then
    ok "Dedicated Filebeat config valid"
  else
    fail "Dedicated Filebeat config invalid"
  fi
  echo "--- Filebeat Elasticsearch output test ---"
  filebeat test output -c filebeat.yml -E "keystore.path=$FB_KEYSTORE" --path.home /usr/share/filebeat --path.config /etc/filebeat-botnet --path.data /var/lib/filebeat-botnet --path.logs /var/log/filebeat-botnet || warn "Elasticsearch connectivity test failed"
fi

for f in "$INSTALL_DIR/logs/botnet_alerts.jsonl" "$INSTALL_DIR/logs/behavior_alerts.jsonl"; do
  if [[ -f "$f" ]]; then
    ok "$f exists ($(wc -l < "$f") lines)"
  else
    warn "$f not created yet; it appears after the first matching alert"
  fi
done

echo "--- recent ML service log ---"
journalctl -u zeek-botnet-detector.service -n 8 --no-pager 2>/dev/null || true
echo "--- recent behavior service log ---"
journalctl -u zeek-behavior-detector.service -n 8 --no-pager 2>/dev/null || true
echo "--- recent dedicated Filebeat log ---"
journalctl -u filebeat-botnet.service -n 8 --no-pager 2>/dev/null || true

echo "Kibana combined Data View: filebeat-*,capstone-zeek-*"
echo "============================================================"
if (( FAILURES == 0 )); then
  echo "Verification finished without hard failures."
  exit 0
else
  echo "Verification finished with $FAILURES hard failure(s)."
  exit 1
fi
