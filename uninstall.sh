#!/usr/bin/env bash
set -Eeuo pipefail
[[ "${EUID:-$(id -u)}" -eq 0 ]] || { echo "Run with sudo"; exit 1; }

CONF="/etc/zeek-botnet-detector.conf"
INSTALL_DIR="/opt/zeek-botnet-detector"
if [[ -r "$CONF" ]]; then
  # shellcheck disable=SC1090
  source "$CONF"
fi

for svc in filebeat-botnet.service zeek-behavior-detector.service zeek-botnet-detector.service zeek-botnet-zeekctl.service; do
  systemctl disable --now "$svc" >/dev/null 2>&1 || true
done
rm -f /etc/systemd/system/filebeat-botnet.service
rm -f /etc/systemd/system/zeek-behavior-detector.service
rm -f /etc/systemd/system/zeek-botnet-detector.service
rm -f /etc/systemd/system/zeek-botnet-zeekctl.service

# Remove ONLY the dedicated Filebeat instance. Never remove the Filebeat package,
# /etc/filebeat/filebeat.yml, or filebeat.service.
rm -rf /etc/filebeat-botnet /var/lib/filebeat-botnet /var/log/filebeat-botnet

# Remove our Zeek load line/file, preserving the rest of local.zeek.
if [[ -n "${LOCAL_ZEEK:-}" && -f "$LOCAL_ZEEK" ]]; then
  sed -i '/# BEGIN zeek-botnet-installer managed load/,/# END zeek-botnet-installer managed load/d' "$LOCAL_ZEEK" || true
fi
if [[ -n "${LOCAL_ZEEK:-}" ]]; then
  rm -f "$(dirname "$LOCAL_ZEEK")/zeek-botnet-detector.zeek"
fi

rm -rf "$INSTALL_DIR"
rm -f "$CONF"
systemctl daemon-reload
systemctl reset-failed || true

echo "Removed Zeek botnet/behavior detector and dedicated Filebeat instance."
echo "Zeek package/config and the existing default Filebeat installation were NOT removed."
