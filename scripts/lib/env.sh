#!/bin/bash
# albus environment & shared utilities

set -u

# System directories
ALBUS_LIB_DIR="/usr/lib/albus"
ALBUS_RUN_DIR="/run/albus"
ALBUS_SOCKET="/tmp/albus.sock"
ALBUS_PID_FILE="$ALBUS_RUN_DIR/albus.pid"
ALBUS_LOG_FILE="$ALBUS_RUN_DIR/albus.log"
ALBUS_LEGACY_PID="/tmp/albus-daemon.pid"

# User directories
ALBUS_USER_CONFIG_DIR="$HOME/.config/omarchy/plugins/io.github.oqullcan.albus"
ALBUS_CONFIG_FILE="$ALBUS_USER_CONFIG_DIR/config.json"
ALBUS_AUTOSTART_DIR="$HOME/.config/autostart"
ALBUS_AUTOSTART_FILE="$ALBUS_AUTOSTART_DIR/io.github.oqullcan.albus.desktop"

# Ports
ALBUS_HTTP_PORT=1080
ALBUS_DNS_PORT=5300

# Terminal colors
c_reset="\033[0m"
c_bold="\033[1m"
c_dim="\033[2m"
c_green="\033[38;2;166;227;161m"
c_cyan="\033[38;2;137;220;235m"
c_magenta="\033[38;2;203;166;247m"
c_yellow="\033[38;2;249;226;175m"
c_red="\033[38;2;243;139;168m"
c_gray="\033[38;2;108;112;134m"

# Get active physical non-loopback network interfaces
get_active_interfaces() {
  local ifaces
  ifaces=$(ip -o link show 2>/dev/null | awk '{print $2}' | tr -d ':' | grep -Ev "^lo$|^tun|^tap|^docker|^veth|^br-|^virbr" || true)
  if [ -z "$ifaces" ]; then
    ifaces=$(resolvectl 2>/dev/null | grep -E "Link [0-9]" | awk '{print $3}' | tr -d '()' | grep -Ev "^lo$" || echo "enp3s0")
  fi
  echo "$ifaces"
}

# Ensure runtime directories exist with proper permissions
ensure_runtime_dir() {
  if [ "$(id -u)" -eq 0 ]; then
    mkdir -p "$ALBUS_RUN_DIR" 2>/dev/null || true
    chmod 755 "$ALBUS_RUN_DIR" 2>/dev/null || true
  fi
}
