#!/usr/bin/env bash
# Turn the maintenance switch of maintenance-gate on or off.
#
# While the switch is on, the gate answers pre-deploy and pre-rollback with
# {"allowed": false, "message": "Deploys paused: <reason> (until <time>)"}.
# The gate reads the switch within STATE_CACHE_SECONDS (default 5 s).
#
# Usage:
#   maintenance.sh on --reason "CNI upgrade" [--for 30m]   # m, h or d; default 1h
#   maintenance.sh off
#   maintenance.sh status
#
# Options (before or after the command):
#   --namespace NS   namespace of the gate (default: extensions)
#   --name NAME      ConfigMap name (default: maintenance-gate-state)
#   --context CTX    kubectl context (default: the current one)
#
# The script writes the ConfigMap with the kubectl rights of the caller.
set -euo pipefail

NAMESPACE="extensions"
NAME="maintenance-gate-state"
KUBECTL=(kubectl)
CMD=""
REASON=""
DURATION="1h"

usage() {
  if [[ "${1:-0}" -eq 0 ]]; then
    sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
  else
    sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//' >&2
  fi
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    on|off|status) CMD="$1" ;;
    --reason) REASON="${2:?--reason needs a value}"; shift ;;
    --for) DURATION="${2:?--for needs a value}"; shift ;;
    --namespace) NAMESPACE="${2:?--namespace needs a value}"; shift ;;
    --name) NAME="${2:?--name needs a value}"; shift ;;
    --context) KUBECTL+=(--context "${2:?--context needs a value}"); shift ;;
    -h|--help) usage 0 ;;
    *) echo "unknown argument: $1" >&2; usage 1 ;;
  esac
  shift
done
[[ -n "$CMD" ]] || usage 1

# JSON string with the characters that need escaping.
json_string() {
  local s=${1//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//[[:cntrl:]]/ }
  printf '"%s"' "$s"
}

# Seconds of a duration such as 30m, 2h or 1d.
duration_seconds() {
  local n=${1%[mhd]} unit=${1: -1}
  [[ "$n" =~ ^[0-9]+$ ]] && (( 10#$n > 0 )) || { echo "invalid duration: $1 (use for example 30m, 2h, 1d)" >&2; exit 1; }
  case "$unit" in
    m) echo $((10#$n * 60)) ;;
    h) echo $((10#$n * 3600)) ;;
    d) echo $((10#$n * 86400)) ;;
    *) echo "invalid duration: $1 (use for example 30m, 2h, 1d)" >&2; exit 1 ;;
  esac
}

# RFC 3339 UTC time for epoch seconds (GNU date or BSD date).
utc_time() {
  date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ
}

write_state() {
  "${KUBECTL[@]}" -n "$NAMESPACE" create configmap "$NAME" \
    --from-literal=state.json="$1" --dry-run=client -o yaml \
    | "${KUBECTL[@]}" apply -f - >/dev/null
}

BY=$(json_string "${USER:-unknown}@$(hostname -s 2>/dev/null || hostname)")

case "$CMD" in
  on)
    [[ -n "$REASON" ]] || { echo "on needs --reason" >&2; exit 1; }
    SECONDS_FOR=$(duration_seconds "$DURATION")
    UNTIL=$(utc_time $(( $(date -u +%s) + SECONDS_FOR )))
    write_state "{\"enabled\": true, \"reason\": $(json_string "$REASON"), \"until\": \"$UNTIL\", \"by\": $BY}"
    echo "Maintenance on until $UNTIL: deploys and rollbacks are paused ($REASON)."
    ;;
  off)
    write_state "{\"enabled\": false, \"by\": $BY}"
    echo "Maintenance off: deploys and rollbacks are allowed again."
    ;;
  status)
    # Other errors (RBAC, context, connection) stop the script: they must not
    # look like "the switch is off".
    STATE=$("${KUBECTL[@]}" -n "$NAMESPACE" get configmap "$NAME" --ignore-not-found -o jsonpath='{.data.state\.json}')
    if [[ -z "$STATE" ]]; then
      echo "No maintenance state ($NAMESPACE/$NAME does not exist or is empty): the switch is off."
      exit 0
    fi
    echo "$STATE"
    UNTIL_NOW=$(printf '%s' "$STATE" | sed -n 's/.*"until": *"\([^"]*\)".*/\1/p')
    if [[ "$STATE" == *'"enabled": true'* && -n "$UNTIL_NOW" && "$UNTIL_NOW" < "$(date -u +%Y-%m-%dT%H:%M:%SZ)" ]]; then
      echo "Expired at $UNTIL_NOW: the gate is open again."
    fi
    ;;
esac
