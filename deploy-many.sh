#!/usr/bin/env bash
set -Eeuo pipefail
[[ $# -ge 1 ]] || { echo "Usage: $0 hosts.txt [remote-install-options...]"; exit 1; }
HOSTS_FILE="$1"; shift
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REMOTE_BASE="/tmp/zeek-botnet-installer-v1.3.1"

while read -r target iface extra; do
  [[ -z "${target:-}" || "$target" == \#* ]] && continue
  [[ -n "${iface:-}" ]] || { echo "Missing interface for $target"; exit 1; }
  echo "=== Deploying to $target ($iface) ==="
  ssh "$target" "rm -rf '$REMOTE_BASE' && mkdir -p '$REMOTE_BASE'"
  scp -qr "$SCRIPT_DIR"/* "$target:$REMOTE_BASE/"
  # Password is intentionally NOT passed on the command line. For unattended
  # deployment, copy a root-only password file separately and pass --es-password-file.
  ssh -t "$target" "cd '$REMOTE_BASE' && chmod +x *.sh && sudo ./install.sh --interface '$iface' $* ${extra:-}"
done < "$HOSTS_FILE"
