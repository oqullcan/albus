#!/bin/bash
# albus system-wide privileged service orchestrator (must execute as root)

set -u

# 1. Security validation: must run as root
if [ "$(id -u)" -ne 0 ]; then
  echo '{"running":false,"error":"albus-service.sh must be executed as root"}' >&2
  exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ALBUS_LIB_DIR="/usr/lib/albus"
ALBUS_RUN_DIR="/run/albus"
ALBUS_SOCKET="/tmp/albus.sock"
ALBUS_PID_FILE="$ALBUS_RUN_DIR/albus.pid"
ALBUS_LOG_FILE="$ALBUS_RUN_DIR/albus.log"
ALBUS_LEGACY_PID="/tmp/albus-daemon.pid"
ALBUS_HTTP_PORT=1080
ALBUS_DNS_PORT=5300

# Get active physical non-loopback network interfaces
get_active_interfaces() {
  local ifaces
  ifaces=$(ip -o link show 2>/dev/null | awk '{print $2}' | tr -d ':' | grep -Ev "^lo$|^tun|^tap|^docker|^veth|^br-|^virbr" || true)
  if [ -z "$ifaces" ]; then
    ifaces=$(resolvectl 2>/dev/null | grep -E "Link [0-9]" | awk '{print $3}' | tr -d '()' | grep -Ev "^lo$" || echo "enp3s0")
  fi
  echo "$ifaces"
}

ensure_runtime_dir() {
  mkdir -p "$ALBUS_RUN_DIR" 2>/dev/null || true
  chmod 755 "$ALBUS_RUN_DIR" 2>/dev/null || true
}

# --- FIREWALL MODULE ---
firewall_disable() {
  while iptables -D OUTPUT -j ALBUS_OUT 2>/dev/null; do :; done
  while iptables -D INPUT -j ALBUS_IN 2>/dev/null; do :; done
  while ip6tables -D OUTPUT -j ALBUS_OUT6 2>/dev/null; do :; done
  while ip6tables -D INPUT -j ALBUS_IN6 2>/dev/null; do :; done

  while iptables -D OUTPUT -j ALBUS_QUIC 2>/dev/null; do :; done
  while ip6tables -D OUTPUT -j ALBUS_V6 2>/dev/null; do :; done
  while ip6tables -D INPUT -j ALBUS_V6_IN 2>/dev/null; do :; done

  while iptables -t nat -D OUTPUT -p tcp -j ALBUS 2>/dev/null; do :; done
  while iptables -t nat -D OUTPUT -j ALBUS 2>/dev/null; do :; done
  while iptables -t nat -D OUTPUT -p udp --dport 53 -j ALBUS_DNS 2>/dev/null; do :; done
  while iptables -t nat -D OUTPUT -p tcp --dport 53 -j ALBUS_DNS 2>/dev/null; do :; done
  while iptables -t nat -D OUTPUT -j ALBUS_DNS 2>/dev/null; do :; done

  while iptables -t nat -D PREROUTING -p tcp -j ALBUS 2>/dev/null; do :; done
  while iptables -t nat -D PREROUTING -p udp --dport 53 -j ALBUS_DNS 2>/dev/null; do :; done
  while iptables -t nat -D PREROUTING -p tcp --dport 53 -j ALBUS_DNS 2>/dev/null; do :; done
  while iptables -t nat -D PREROUTING -j ALBUS 2>/dev/null; do :; done
  while iptables -t nat -D PREROUTING -j ALBUS_DNS 2>/dev/null; do :; done

  while iptables -t mangle -D OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360 2>/dev/null; do :; done

  iptables -F ALBUS_OUT 2>/dev/null || true
  iptables -X ALBUS_OUT 2>/dev/null || true
  iptables -F ALBUS_IN 2>/dev/null || true
  iptables -X ALBUS_IN 2>/dev/null || true
  ip6tables -F ALBUS_OUT6 2>/dev/null || true
  ip6tables -X ALBUS_OUT6 2>/dev/null || true
  ip6tables -F ALBUS_IN6 2>/dev/null || true
  ip6tables -X ALBUS_IN6 2>/dev/null || true

  iptables -F ALBUS_QUIC 2>/dev/null || true
  iptables -X ALBUS_QUIC 2>/dev/null || true
  ip6tables -F ALBUS_V6 2>/dev/null || true
  ip6tables -X ALBUS_V6 2>/dev/null || true
  ip6tables -F ALBUS_V6_IN 2>/dev/null || true
  ip6tables -X ALBUS_V6_IN 2>/dev/null || true

  iptables -t nat -F ALBUS 2>/dev/null || true
  iptables -t nat -X ALBUS 2>/dev/null || true
  iptables -t nat -F ALBUS_DNS 2>/dev/null || true
  iptables -t nat -X ALBUS_DNS 2>/dev/null || true

  while iptables -D OUTPUT -p udp --dport 53 -j DROP 2>/dev/null; do :; done
  while iptables -D OUTPUT -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null; do :; done
  while ip6tables -D OUTPUT -p tcp -m multiport --dports 80,443 -j REJECT --reject-with tcp-reset 2>/dev/null; do :; done
  while ip6tables -D OUTPUT -p udp --dport 443 -j REJECT 2>/dev/null; do :; done
  while ip6tables -D OUTPUT -p udp --dport 53 -j REJECT 2>/dev/null; do :; done

  if command -v conntrack >/dev/null 2>&1; then
    conntrack -F 2>/dev/null || true
  fi
}

firewall_enable() {
  local http_port="${1:-1080}"
  local custom_bootstraps="${2:-}"

  firewall_disable

  iptables -N ALBUS_OUT
  iptables -A ALBUS_OUT -m mark --mark 0x1337 -j RETURN
  iptables -A ALBUS_OUT -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable

  iptables -N ALBUS_IN
  iptables -A ALBUS_IN ! -i lo -p tcp --dport "$http_port" -j DROP
  iptables -A ALBUS_IN ! -i lo -p udp --dport 5300 -j DROP
  iptables -A ALBUS_IN ! -i lo -p tcp --dport 5300 -j DROP

  ip6tables -N ALBUS_OUT6
  ip6tables -A ALBUS_OUT6 -p tcp -m multiport --dports 80,443 -j REJECT --reject-with tcp-reset
  ip6tables -A ALBUS_OUT6 -p udp --dport 443 -j REJECT
  ip6tables -A ALBUS_OUT6 -p udp --dport 53 -j REJECT

  ip6tables -N ALBUS_IN6
  ip6tables -A ALBUS_IN6 ! -i lo -p tcp --dport "$http_port" -j DROP
  ip6tables -A ALBUS_IN6 ! -i lo -p udp --dport 5300 -j DROP
  ip6tables -A ALBUS_IN6 ! -i lo -p tcp --dport 5300 -j DROP

  iptables -t nat -N ALBUS
  iptables -t nat -A ALBUS -m mark --mark 0x1337 -j RETURN
  iptables -t nat -A ALBUS -d 0.0.0.0/8 -j RETURN
  iptables -t nat -A ALBUS -d 10.0.0.0/8 -j RETURN
  iptables -t nat -A ALBUS -d 127.0.0.0/8 -j RETURN
  iptables -t nat -A ALBUS -d 169.254.0.0/16 -j RETURN
  iptables -t nat -A ALBUS -d 172.16.0.0/12 -j RETURN
  iptables -t nat -A ALBUS -d 192.168.0.0/16 -j RETURN

  iptables -t nat -A ALBUS -d 9.9.9.9 -j RETURN
  iptables -t nat -A ALBUS -d 149.112.112.112 -j RETURN
  iptables -t nat -A ALBUS -d 1.1.1.1 -j RETURN
  iptables -t nat -A ALBUS -d 1.0.0.1 -j RETURN
  iptables -t nat -A ALBUS -d 94.140.14.14 -j RETURN
  iptables -t nat -A ALBUS -d 94.140.15.15 -j RETURN
  iptables -t nat -A ALBUS -d 45.90.28.0/24 -j RETURN
  iptables -t nat -A ALBUS -d 45.90.30.0/24 -j RETURN

  if [ -n "$custom_bootstraps" ]; then
    IFS=',' read -ra ADDR <<< "$custom_bootstraps"
    for ip in "${ADDR[@]}"; do
      trimmed=$(echo "$ip" | xargs)
      if [[ $trimmed =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        iptables -t nat -A ALBUS -d "$trimmed" -j RETURN
      fi
    done
  fi

  iptables -t nat -A ALBUS -p tcp --dport 80 -j REDIRECT --to-ports "$http_port"
  iptables -t nat -A ALBUS -p tcp --dport 443 -j REDIRECT --to-ports "$http_port"

  iptables -t nat -N ALBUS_DNS
  iptables -t nat -A ALBUS_DNS -m mark --mark 0x1337 -j RETURN
  iptables -t nat -A ALBUS_DNS -d 127.0.0.0/8 -j RETURN
  iptables -t nat -A ALBUS_DNS -d 10.0.0.0/8 -j RETURN
  iptables -t nat -A ALBUS_DNS -d 172.16.0.0/12 -j RETURN
  iptables -t nat -A ALBUS_DNS -d 192.168.0.0/16 -j RETURN
  iptables -t nat -A ALBUS_DNS -p udp --dport 53 -j REDIRECT --to-ports 5300
  iptables -t nat -A ALBUS_DNS -p tcp --dport 53 -j REDIRECT --to-ports 5300

  iptables -I OUTPUT 1 -j ALBUS_OUT
  iptables -I INPUT 1 -j ALBUS_IN
  ip6tables -I OUTPUT 1 -j ALBUS_OUT6
  ip6tables -I INPUT 1 -j ALBUS_IN6

  iptables -t nat -I OUTPUT 1 -p tcp -j ALBUS
  iptables -t nat -I OUTPUT 1 -p udp --dport 53 -j ALBUS_DNS
  iptables -t nat -I OUTPUT 1 -p tcp --dport 53 -j ALBUS_DNS
  iptables -t mangle -I OUTPUT 1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360 2>/dev/null || true
}

# --- DNS MODULE ---
dns_set_albus() {
  local ifaces
  ifaces=$(get_active_interfaces)
  for iface in $ifaces; do
    resolvectl dns "$iface" 127.0.0.1:5300 2>/dev/null || true
    resolvectl domain "$iface" "~." 2>/dev/null || true
    resolvectl default-route "$iface" true 2>/dev/null || true
    resolvectl dnsovertls "$iface" no 2>/dev/null || true
    resolvectl dnssec "$iface" no 2>/dev/null || true
  done
  resolvectl flush-caches 2>/dev/null || true
}

dns_restore_system() {
  local ifaces
  ifaces=$(get_active_interfaces)

  local gw
  gw=$(ip route show default 2>/dev/null | awk '{print $3}' | head -n 1 || true)

  local nameservers=("1.1.1.1" "8.8.8.8" "1.0.0.1")
  if [ -n "$gw" ] && [[ $gw =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    nameservers+=("$gw")
  fi

  for iface in $ifaces; do
    resolvectl revert "$iface" 2>/dev/null || true
    resolvectl default-route "$iface" true 2>/dev/null || true
    resolvectl domain "$iface" "" 2>/dev/null || true
    resolvectl dnsovertls "$iface" opportunistic 2>/dev/null || true
    resolvectl dnssec "$iface" no 2>/dev/null || true
    resolvectl dns "$iface" "${nameservers[@]}" 2>/dev/null || true
  done

  if [ -f /run/systemd/resolve/stub-resolv.conf ]; then
    ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf 2>/dev/null || true
  fi

  resolvectl flush-caches 2>/dev/null || true
  ip route flush cache 2>/dev/null || true
}

# --- PROCESS MODULE ---
process_stop() {
  if [ -f "$ALBUS_PID_FILE" ]; then
    local pid
    pid=$(cat "$ALBUS_PID_FILE" 2>/dev/null || true)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      kill -15 "$pid" 2>/dev/null || true
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

process_start() {
  local binary="$1"
  local mode="$2"
  local dns="$3"
  local bootstrap="${4:-}"
  local whitelist="${5:-}"

  process_stop
  ensure_runtime_dir

  local cmd=("$binary" "--mode" "$mode" "--dns" "$dns")
  if [ -n "$bootstrap" ]; then
    cmd+=("--bootstrap" "$bootstrap")
  fi
  if [ -n "$whitelist" ]; then
    cmd+=("--whitelist" "$whitelist")
  fi

  touch "$ALBUS_LOG_FILE"
  chmod 666 "$ALBUS_LOG_FILE" 2>/dev/null || true
  setsid "${cmd[@]}" > "$ALBUS_LOG_FILE" 2>&1 &
  local daemon_pid=$!

  echo "$daemon_pid" > "$ALBUS_PID_FILE"
  chmod 666 "$ALBUS_PID_FILE" 2>/dev/null || true

  sleep 0.2
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    local err
    err=$(tail -n 3 "$ALBUS_LOG_FILE" 2>/dev/null | tr -d '"\r\n' || echo "daemon failed to start")
    echo "{\"running\":false,\"error\":\"$err\"}"
    return 1
  fi

  sleep 0.05
  chmod 666 "$ALBUS_SOCKET" 2>/dev/null || true

  echo "$daemon_pid"
  return 0
}

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

# --- SYSTEM SYNC MODULE ---
system_sync() {
  local binary="${1:-}"

  mkdir -p "$ALBUS_LIB_DIR/lib" "/usr/share/polkit-1/actions" 2>/dev/null || true

  if [ -n "$binary" ] && [ -x "$binary" ]; then
    install -m755 "$binary" "$ALBUS_LIB_DIR/albus-core" 2>/dev/null || true
  fi

  local src_dir=""
  for u in /home/*; do
    for cand in "$u/albusdev/scripts" "$u/.config/omarchy/plugins/io.github.oqullcan.albus/scripts"; do
      if [ -f "$cand/albus-service.sh" ]; then
        src_dir="$cand"
        break 2
      fi
    done
  done

  if [ -n "$src_dir" ] && [ "$src_dir" != "$ALBUS_LIB_DIR" ]; then
    install -m755 "$src_dir/albus-service.sh" "$ALBUS_LIB_DIR/albus-service.sh" 2>/dev/null || true
    install -m755 "$src_dir/albus-transparent.sh" "$ALBUS_LIB_DIR/albus-transparent.sh" 2>/dev/null || true
    if [ -d "$src_dir/lib" ]; then
      install -m755 "$src_dir/lib/"*.sh "$ALBUS_LIB_DIR/lib/" 2>/dev/null || true
    fi
  fi
}

action="${1:-start}"
mode="${2:-auto}"
dns="${3:-quad9}"
bootstrap="${4:-}"
whitelist="${5:-}"
provided_bin="${6:-}"

binary=""
if [ -n "$provided_bin" ] && [ -x "$provided_bin" ]; then
  binary="$provided_bin"
elif [ -x "$ALBUS_LIB_DIR/albus-core" ]; then
  binary="$ALBUS_LIB_DIR/albus-core"
elif [ -x "/usr/bin/albus-core" ]; then
  binary="/usr/bin/albus-core"
else
  for u in /home/*; do
    for cand in "$u/.config/omarchy/plugins/io.github.oqullcan.albus/bin/albus-core" "$u/albusdev/bin/albus-core" "$u/albusdev/core/target/release/albus-core"; do
      if [ -x "$cand" ]; then
        binary="$cand"
        break 2
      fi
    done
  done
fi

case "$action" in
  start)
    if [ -z "$binary" ] || [ ! -x "$binary" ]; then
      echo '{"running":false,"error":"albus-core binary not found"}'
      exit 1
    fi

    system_sync "$binary"
    daemon_pid=$(process_start "$binary" "$mode" "$dns" "$bootstrap" "$whitelist")
    if [ $? -ne 0 ]; then
      exit 1
    fi
    firewall_enable "$ALBUS_HTTP_PORT" "$bootstrap"
    dns_set_albus

    echo "{\"running\":true,\"pid\":$daemon_pid,\"mode\":\"$mode\",\"dns\":\"$dns\"}"
    ;;

  stop)
    firewall_disable
    dns_restore_system
    process_stop
    system_sync

    echo '{"running":false}'
    ;;

  fix-network|repair)
    firewall_disable
    dns_restore_system
    process_stop
    system_sync "$binary"

    echo '{"repaired":true,"message":"Network completely reset to system defaults"}'
    ;;

  status)
    if process_is_running; then
      echo '{"running":true}'
    else
      echo '{"running":false}'
    fi
    ;;

  *)
    echo "Usage: $0 {start|stop|fix-network|repair|status}"
    exit 1
    ;;
esac
