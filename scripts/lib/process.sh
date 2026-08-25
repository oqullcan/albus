#!/bin/bash
# albus daemon process & supervisor module

set -u

# Gracefully stop the albus-core background daemon
process_stop() {
  if [ -f "$ALBUS_PID_FILE" ]; then
    local pid
    pid=$(cat "$ALBUS_PID_FILE" 2>/dev/null || true)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      kill -15 "$pid" 2>/dev/null || true
      # Wait up to 200ms for clean socket closure
      for _ in {1..4}; do
        if ! kill -0 "$pid" 2>/dev/null; then break; fi
        sleep 0.05
      done
      if kill -0 "$pid" 2>/dev/null; then
        kill -9 "$pid" 2>/dev/null || true
      fi
    fi
    rm -f "$ALBUS_PID_FILE"
  fi

  pkill -15 -x "albus-core" 2>/dev/null || true
  sleep 0.05
  pkill -9 -x "albus-core" 2>/dev/null || true

  rm -f "$ALBUS_SOCKET" "$ALBUS_LOG_FILE" "$ALBUS_LEGACY_PID" 2>/dev/null || true
}

# Start the albus-core background daemon
process_start() {
  local binary="$1"
  local mode="$2"
  local dns="$3"
  local bootstrap="${4:-}"
  local whitelist="${5:-}"

  # Clean any lingering instances first
  process_stop
  ensure_runtime_dir

  # Build execution command
  local cmd=("$binary" "--mode" "$mode" "--dns" "$dns")
  if [ -n "$bootstrap" ]; then
    cmd+=("--bootstrap" "$bootstrap")
  fi
  if [ -n "$whitelist" ]; then
    cmd+=("--whitelist" "$whitelist")
  fi

  # Start daemon in new session detached
  touch "$ALBUS_LOG_FILE"
  chmod 666 "$ALBUS_LOG_FILE" 2>/dev/null || true
  setsid "${cmd[@]}" > "$ALBUS_LOG_FILE" 2>&1 &
  local daemon_pid=$!

  echo "$daemon_pid" > "$ALBUS_PID_FILE"
  chmod 666 "$ALBUS_PID_FILE" 2>/dev/null || true

  # Verify daemon liveliness
  sleep 0.2
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    local err
    err=$(tail -n 3 "$ALBUS_LOG_FILE" 2>/dev/null | tr -d '"\r\n' || echo "daemon failed to start")
    echo "{\"running\":false,\"error\":\"$err\"}"
    return 1
  fi

  # Ensure Unix socket is world-accessible for UI IPC status polling
  sleep 0.05
  chmod 666 "$ALBUS_SOCKET" 2>/dev/null || true

  echo "$daemon_pid"
  return 0
}

# Check if albus-core is currently running
process_is_running() {
  if [ -f "$ALBUS_PID_FILE" ]; then
    local pid
    pid=$(cat "$ALBUS_PID_FILE" 2>/dev/null || true)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      return 0
    fi
  fi
  pgrep -x "albus-core" >/dev/null 2>&1
}
