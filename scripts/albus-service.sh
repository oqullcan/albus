#!/bin/bash
# albus system-wide privileged service helper (must execute as root)

set -euo pipefail

# 1. security validation: must run as root
if [ "$(id -u)" -ne 0 ]; then
  echo "{\"running\":false,\"error\":\"albus-service.sh must be executed as root\"}" >&2
  exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

action="${1:-start}"
mode="${2:-auto}"
dns="${3:-quad9}"
bootstrap="${4:-}"
whitelist="${5:-}"
provided_bin="${6:-}"

# 2. resolve core binary
binary=""
if [ -n "$provided_bin" ] && [ -x "$provided_bin" ]; then
  binary="$provided_bin"
elif [ -x "/usr/lib/albus/albus-core" ]; then
  binary="/usr/lib/albus/albus-core"
elif [ -x "/usr/bin/albus-core" ]; then
  binary="/usr/bin/albus-core"
elif [ -x "$script_dir/../bin/albus-core" ]; then
  binary="$script_dir/../bin/albus-core"
elif [ -x "$script_dir/../core/target/release/albus-core" ]; then
  binary="$script_dir/../core/target/release/albus-core"
else
  for u in /home/*; do
    if [ -x "$u/.config/omarchy/plugins/io.github.oqullcan.albus/bin/albus-core" ]; then
      binary="$u/.config/omarchy/plugins/io.github.oqullcan.albus/bin/albus-core"
      break
    elif [ -x "$u/albusdev/bin/albus-core" ]; then
      binary="$u/albusdev/bin/albus-core"
      break
    elif [ -x "$u/.config/omarchy/plugins/io.github.oqullcan.albus/core/target/release/albus-core" ]; then
      binary="$u/.config/omarchy/plugins/io.github.oqullcan.albus/core/target/release/albus-core"
      break
    fi
  done
fi

if [ -z "$binary" ] || [ ! -x "$binary" ]; then
  echo "{\"running\":false,\"error\":\"albus-core binary not found\"}"
  exit 1
fi

# Sync root helper and binary to /usr/lib/albus
mkdir -p /usr/lib/albus /usr/share/polkit-1/actions 2>/dev/null || true
install -m755 "$binary" /usr/lib/albus/albus-core 2>/dev/null || true
if [ "$script_dir" != "/usr/lib/albus" ] && [ -f "$script_dir/albus-service.sh" ]; then
  install -m755 "$script_dir/albus-service.sh" /usr/lib/albus/albus-service.sh 2>/dev/null || true
  install -m755 "$script_dir/albus-transparent.sh" /usr/lib/albus/albus-transparent.sh 2>/dev/null || true
fi



# 3. resolve transparent script
transparent_script="$script_dir/albus-transparent.sh"
if [ ! -x "$transparent_script" ] && [ -x "/usr/lib/albus/albus-transparent.sh" ]; then
  transparent_script="/usr/lib/albus/albus-transparent.sh"
fi

run_dir="/run/albus"
mkdir -p "$run_dir" 2>/dev/null || run_dir="/tmp/albus"
mkdir -p "$run_dir"
chmod 755 "$run_dir" 2>/dev/null || true

pid_file="$run_dir/albus.pid"
log_file="$run_dir/albus.log"
legacy_pid="/tmp/albus-daemon.pid"

get_interfaces() {
  resolvectl 2>/dev/null | grep -E "Link [0-9]" | awk '{print $3}' | tr -d '()' || echo "enp3s0"
}

case "$action" in
  start)
    # clean previous instances
    pkill -9 -x "albus-core" 2>/dev/null || true

    rm -f "$pid_file" "$log_file" "$legacy_pid" /tmp/albus.sock 2>/dev/null || true
    sleep 0.05

    # build command
    cmd=("$binary" "--mode" "$mode" "--dns" "$dns")
    if [ -n "$bootstrap" ]; then
      cmd+=("--bootstrap" "$bootstrap")
    fi
    if [ -n "$whitelist" ]; then
      cmd+=("--whitelist" "$whitelist")
    fi

    # start background daemon as root
    touch "$log_file"
    chmod 666 "$log_file" 2>/dev/null || true
    setsid "${cmd[@]}" > "$log_file" 2>&1 &
    daemon_pid=$!
    echo "$daemon_pid" > "$pid_file"
    chmod 666 "$pid_file" 2>/dev/null || true

    # verify daemon is alive
    sleep 0.2
    if ! kill -0 "$daemon_pid" 2>/dev/null; then
      err=$(cat "$log_file" 2>/dev/null | tail -n 3 | tr -d '"\r\n' || echo "daemon failed to start")
      echo "{\"running\":false,\"error\":\"$err\"}"
      exit 1
    fi


    # enable netfilter transparent interception
    if [ -x "$transparent_script" ]; then
      "$transparent_script" enable "$bootstrap"
    fi

    resolvectl flush-caches 2>/dev/null || true

    # ensure control socket is world-accessible for UI IPC status polling
    sleep 0.05
    chmod 666 /tmp/albus.sock 2>/dev/null || true

    echo "{\"running\":true,\"pid\":$daemon_pid,\"mode\":\"$mode\",\"dns\":\"$dns\"}"
    ;;

  stop)
    # 1. disable transparent netfilter rules
    if [ -x "$transparent_script" ]; then
      "$transparent_script" disable 2>/dev/null || true
    fi

    # 2. ensure network interfaces have valid default-route and DNS scopes
    for iface in $(get_interfaces); do
      resolvectl default-route "$iface" true 2>/dev/null || true
      if resolvectl status "$iface" 2>/dev/null | grep -q "Current Scopes: none"; then
        resolvectl dns "$iface" 8.8.8.8 8.8.4.4 2>/dev/null || true
      fi
    done
    resolvectl flush-caches 2>/dev/null || true

    # 3. flush routing cache
    ip route flush cache 2>/dev/null || true

    # 4. kill daemon
    if [ -f "$pid_file" ]; then
      pid=$(cat "$pid_file" 2>/dev/null || true)
      if [ -n "$pid" ]; then
        kill -9 "$pid" 2>/dev/null || true
      fi
      rm -f "$pid_file"
    fi
    pkill -9 -x "albus-core" 2>/dev/null || true
    rm -f /tmp/albus.sock "$log_file" "$legacy_pid" 2>/dev/null || true

    # 5. sync helpers
    if [ "$script_dir" != "/usr/lib/albus" ] && [ -f "$script_dir/albus-service.sh" ]; then
      install -m755 "$script_dir/albus-service.sh" /usr/lib/albus/albus-service.sh 2>/dev/null || true
      install -m755 "$script_dir/albus-transparent.sh" /usr/lib/albus/albus-transparent.sh 2>/dev/null || true
    fi

    echo "{\"running\":false}"
    ;;

  fix-network|repair)
    # 1. Kill any running albus process
    if [ -f "$pid_file" ]; then
      pid=$(cat "$pid_file" 2>/dev/null || true)
      if [ -n "$pid" ]; then kill -9 "$pid" 2>/dev/null || true; fi
      rm -f "$pid_file"
    fi
    pkill -9 -x "albus-core" 2>/dev/null || true
    rm -f "$pid_file" "$log_file" /tmp/albus.sock "$legacy_pid" 2>/dev/null || true

    # 2. Complete firewall rule teardown (IPv4 + IPv6)
    if [ -x "$transparent_script" ]; then
      "$transparent_script" disable 2>/dev/null || true
    fi

    # 3. Complete DNS & systemd-resolved reset
    for iface in $(get_interfaces); do
      resolvectl default-route "$iface" true 2>/dev/null || true
      resolvectl dns "$iface" 8.8.8.8 8.8.4.4 2>/dev/null || true
    done
    resolvectl flush-caches 2>/dev/null || true

    # 4. Route and ARP cache flush
    ip route flush cache 2>/dev/null || true

    # 5. Sync root helper files and permissions
    mkdir -p /usr/lib/albus /usr/share/polkit-1/actions 2>/dev/null || true
    if [ -x "$binary" ]; then
      install -m755 "$binary" /usr/lib/albus/albus-core 2>/dev/null || true
    fi
    if [ "$script_dir" != "/usr/lib/albus" ] && [ -f "$script_dir/albus-service.sh" ]; then
      install -m755 "$script_dir/albus-service.sh" /usr/lib/albus/albus-service.sh 2>/dev/null || true
      install -m755 "$script_dir/albus-transparent.sh" /usr/lib/albus/albus-transparent.sh 2>/dev/null || true
    fi

    echo "{\"repaired\":true,\"message\":\"Network completely reset to system defaults\"}"
    ;;


esac
