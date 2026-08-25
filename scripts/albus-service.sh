#!/bin/bash
# albus service manager

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(dirname "$script_dir")"
binary="$project_dir/core/target/release/albus-core"

run_dir="/run/albus"
mkdir -p "$run_dir" 2>/dev/null || run_dir="/tmp/albus"
mkdir -p "$run_dir"
chmod 755 "$run_dir" 2>/dev/null || true

pid_file="$run_dir/albus.pid"
log_file="$run_dir/albus.log"

action="${1:-start}"
mode="${2:-auto}"
dns="${3:-quad9}"
bootstrap="${4:-}"
whitelist="${5:-}"

get_interfaces() {
  resolvectl 2>/dev/null | grep -E "Link [0-9]" | awk '{print $3}' | tr -d '()' || echo "enp3s0"
}

case "$action" in
  start)
    pkill -9 -f "albus-core" 2>/dev/null || true
    rm -f "$pid_file" "$log_file" /tmp/albus.sock 2>/dev/null || true
    sleep 0.05

    cmd=("$binary" "--mode" "$mode" "--dns" "$dns")
    if [ -n "$bootstrap" ]; then cmd+=("--bootstrap" "$bootstrap"); fi
    if [ -n "$whitelist" ]; then cmd+=("--whitelist" "$whitelist"); fi

    touch "$log_file"
    chmod 666 "$log_file" 2>/dev/null || true
    setsid "${cmd[@]}" > "$log_file" 2>&1 &
    daemon_pid=$!
    echo "$daemon_pid" > "$pid_file"
    chmod 666 "$pid_file" 2>/dev/null || true

    sleep 0.2
    if ! kill -0 "$daemon_pid" 2>/dev/null; then
      echo "{\"running\":false,\"error\":\"daemon failed to start\"}"
      exit 1
    fi

    "$script_dir/albus-transparent.sh" enable "$bootstrap"

    for iface in $(get_interfaces); do
      resolvectl dns "$iface" 127.0.0.1:5300 2>/dev/null || true
      resolvectl domain "$iface" "~." 2>/dev/null || true
      resolvectl default-route "$iface" true 2>/dev/null || true
    done
    resolvectl flush-caches 2>/dev/null || true

    sleep 0.05
    chmod 666 /tmp/albus.sock 2>/dev/null || true
    echo "{\"running\":true,\"pid\":$daemon_pid,\"mode\":\"$mode\",\"dns\":\"$dns\"}"
    ;;

  stop)
    for iface in $(get_interfaces); do
      resolvectl revert "$iface" 2>/dev/null || true
    done
    resolvectl flush-caches 2>/dev/null || true
    "$script_dir/albus-transparent.sh" disable 2>/dev/null || true

    if [ -f "$pid_file" ]; then
      pid=$(cat "$pid_file" 2>/dev/null || true)
      if [ -n "$pid" ]; then kill -9 "$pid" 2>/dev/null || true; fi
      rm -f "$pid_file"
    fi
    pkill -9 -f "albus-core" 2>/dev/null || true
    rm -f /tmp/albus.sock 2>/dev/null || true
    echo "{\"running\":false}"
    ;;

  fix-network|repair)
    for iface in $(get_interfaces); do
      resolvectl revert "$iface" 2>/dev/null || true
    done
    "$script_dir/albus-transparent.sh" disable 2>/dev/null || true
    pkill -9 -f "albus-core" 2>/dev/null || true
    rm -f "$pid_file" "$log_file" /tmp/albus.sock 2>/dev/null || true
    resolvectl flush-caches 2>/dev/null || true
    echo "{\"repaired\":true}"
    ;;
esac
