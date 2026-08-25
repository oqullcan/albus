#!/bin/bash
# albus IPC & diagnostic communication module

set -u

# Query the status from running albus-core instance
ipc_get_status() {
  local binary="$1"

  # Fast path: query core binary CLI status flag
  if [ -x "$binary" ]; then
    local out
    out=$("$binary" --status 2>/dev/null || true)
    if [ -n "$out" ] && [ "$out" != '{"running":false}' ]; then
      echo "$out"
      return 0
    fi
  fi

  # Socket path fallback
  if [ -S "$ALBUS_SOCKET" ] && command -v socat >/dev/null 2>&1; then
    local out
    out=$(echo "STATUS" | socat -t 0.3 - "UNIX-CONNECT:$ALBUS_SOCKET" 2>/dev/null || true)
    if [ -n "$out" ]; then
      echo "$out"
      return 0
    fi
  fi

  echo '{"running":false}'
}

# Query comprehensive diagnostic report from albus-core
ipc_get_diagnose() {
  local binary="$1"

  if [ -x "$binary" ]; then
    local out
    out=$("$binary" --diagnose 2>/dev/null || true)
    if [ -n "$out" ]; then
      echo "$out"
      return 0
    fi
  fi

  echo '{"success":false,"error":"daemon not reachable"}'
}

# Send desktop notification for evasion events
ipc_notify_evasion() {
  local target="${1:-unknown}"
  if command -v notify-send >/dev/null 2>&1; then
    notify-send -a "Albus" -i "security-high" "DPI Bypassed" "Secured connection to $target" 2>/dev/null || true
  fi
}
