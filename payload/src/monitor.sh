#!/usr/bin/env bash
set -u
BASE="/opt/zeek-botnet-detector/logs"
DETECTION_LOG="$BASE/detections.jsonl"
BOTNET_LOG="$BASE/botnet_alerts.jsonl"
BEHAVIOR_LOG="$BASE/behavior_alerts.jsonl"
REFRESH="${REFRESH:-2}"
ROWS="${ROWS:-10}"

GREEN='\033[0;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

command -v jq >/dev/null 2>&1 || { echo "jq is required"; exit 1; }

count_lines() {
  [[ -f "$1" ]] && wc -l < "$1" || echo 0
}

while true; do
  clear
  TOTAL=$(count_lines "$DETECTION_LOG")
  BOTNET=$(count_lines "$BOTNET_LOG")
  BEHAVIOR=$(count_lines "$BEHAVIOR_LOG")
  NORMAL=$(( TOTAL >= BOTNET ? TOTAL - BOTNET : 0 ))

  echo -e "${CYAN}${BOLD}============================================================================================================${RESET}"
  echo -e "${CYAN}${BOLD}                         ZEEK BOTNET + BEHAVIOR REAL-TIME MONITOR${RESET}"
  echo -e "${CYAN}${BOLD}============================================================================================================${RESET}"
  printf " Host               : %s\n" "$(hostname)"
  printf " Mode               : SHADOW\n"
  printf " ML threshold       : 0.50\n"
  echo
  echo -e " Total predictions  : ${BOLD}${TOTAL}${RESET}"
  echo -e " Normal             : ${GREEN}${NORMAL}${RESET}"
  echo -e " ML Botnet alerts   : ${RED}${BOTNET}${RESET}"
  echo -e " Behavior alerts    : ${YELLOW}${BEHAVIOR}${RESET}"
  echo
  echo -e "${BOLD}LATEST ML PREDICTIONS${RESET}"
  printf "%-10s %-29s %-29s %-7s %-9s %-10s\n" TIME SOURCE DESTINATION PROTO PROB RESULT
  printf "%-10s %-29s %-29s %-7s %-9s %-10s\n" ---------- ----------------------------- ----------------------------- ------- --------- ----------
  if [[ -s "$DETECTION_LOG" ]]; then
    tail -n "$ROWS" "$DETECTION_LOG" | jq -r '
      [
        ((.processed_at_utc // "-") | if . == "-" then . else (split("T")[1] | split(".")[0]) end),
        ((.src_ip // "-") + ":" + ((.src_port // "-")|tostring)),
        ((.dst_ip // "-") + ":" + ((.dst_port // "-")|tostring)),
        (.proto // "-"),
        ((.botnet_probability // 0)|tostring),
        (.prediction // "-")
      ] | @tsv' | while IFS=$'\t' read -r T S D P PR R; do
        PF=$(printf '%.4f' "$PR" 2>/dev/null || printf '%s' "$PR")
        if [[ "$R" == "BOTNET" ]]; then C="$RED"; else C="$GREEN"; fi
        printf "%-10s %-29s %-29s %-7s %-9s ${C}%-10s${RESET}\n" "$T" "$S" "$D" "$P" "$PF" "$R"
      done
  else
    echo " No ML predictions yet."
  fi

  echo
  echo -e "${BOLD}LATEST BEHAVIOR ALERTS${RESET}"
  printf "%-10s %-27s %-18s %-18s %-8s\n" TIME TYPE SOURCE DESTINATION VALUE
  printf "%-10s %-27s %-18s %-18s %-8s\n" ---------- --------------------------- ------------------ ------------------ --------
  if [[ -s "$BEHAVIOR_LOG" ]]; then
    tail -n 5 "$BEHAVIOR_LOG" | jq -r '
      [
        ((.processed_at_utc // "-") | if . == "-" then . else (split("T")[1] | split(".")[0]) end),
        (.alert_type // "-"),
        (.src_ip // "-"),
        ((.dst_ip // "-") + ":" + ((.dst_port // "-")|tostring)),
        ((.attempts_in_window // .unique_destination_ports // .unique_destination_hosts // .connections_in_window // .connections_observed // "-")|tostring)
      ] | @tsv' | while IFS=$'\t' read -r T TY S D V; do
        printf "%-10s ${YELLOW}%-27s${RESET} %-18s %-18s %-8s\n" "$T" "$TY" "$S" "$D" "$V"
      done
  else
    echo " No behavior alerts yet."
  fi

  echo
  echo -e "${CYAN}------------------------------------------------------------------------------------------------------------${RESET}"
  echo " Refresh every ${REFRESH}s | Ctrl+C to exit"
  sleep "$REFRESH"
done
