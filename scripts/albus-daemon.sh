#!/bin/bash
# albus user daemon & CLI gateway

set -u

# Ensure no proxy environment variables pollute user session
unset all_proxy ALL_PROXY http_proxy HTTP_PROXY https_proxy HTTPS_PROXY ftp_proxy FTP_PROXY 2>/dev/null || true

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "$script_dir/.." && pwd)"

ALBUS_LIB_DIR="/usr/lib/albus"
ALBUS_SOCKET="/tmp/albus.sock"
ALBUS_LOG_FILE="/run/albus/albus.log"
ALBUS_USER_CONFIG_DIR="$HOME/.config/omarchy/plugins/io.github.oqullcan.albus"
ALBUS_CONFIG_FILE="$ALBUS_USER_CONFIG_DIR/config.json"
ALBUS_AUTOSTART_DIR="$HOME/.config/autostart"
ALBUS_AUTOSTART_FILE="$ALBUS_AUTOSTART_DIR/io.github.oqullcan.albus.desktop"

c_reset="\033[0m"
c_bold="\033[1m"
c_dim="\033[2m"
c_green="\033[38;2;166;227;161m"
c_magenta="\033[38;2;203;166;247m"

resolve_binary() {
  local binary=""
  if [ -x "$ALBUS_LIB_DIR/albus-core" ]; then
    binary="$ALBUS_LIB_DIR/albus-core"
  elif [ -x "$project_dir/bin/albus-core" ]; then
    binary="$project_dir/bin/albus-core"
  elif [ -x "$project_dir/core/target/release/albus-core" ]; then
    binary="$project_dir/core/target/release/albus-core"
  elif [ -x "/usr/bin/albus-core" ]; then
    binary="/usr/bin/albus-core"
  elif [ -x "$HOME/.config/omarchy/plugins/io.github.oqullcan.albus/bin/albus-core" ]; then
    binary="$HOME/.config/omarchy/plugins/io.github.oqullcan.albus/bin/albus-core"
  fi
  echo "$binary"
}

exec_privileged() {
  local helper="$script_dir/albus-service.sh"
  if [ -x "$ALBUS_LIB_DIR/albus-service.sh" ]; then
    helper="$ALBUS_LIB_DIR/albus-service.sh"
  fi

  if [ "$(id -u)" -eq 0 ]; then
    "$helper" "$@"
  elif command -v pkexec >/dev/null 2>&1; then
    pkexec "$helper" "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$helper" "$@"
  else
    echo '{"running":false,"error":"Neither pkexec nor sudo found"}'
    exit 1
  fi
}

cmd="${1:-status}"
shift || true

case "$cmd" in
  get-config)
    if [ -f "$ALBUS_CONFIG_FILE" ]; then
      cat "$ALBUS_CONFIG_FILE"
    else
      echo '{"mode":"auto","dns":"quad9","custom_url":"","custom_primary":"","custom_secondary":"","whitelist":"","autostart":false,"notifications":true}'
    fi
    ;;

  save-config)
    mode="${1:-auto}"
    dns="${2:-quad9}"
    custom_url="${3:-}"
    custom_primary="${4:-}"
    custom_secondary="${5:-}"
    whitelist="${6:-}"
    autostart="${7:-false}"
    notifications="${8:-true}"

    mkdir -p "$ALBUS_USER_CONFIG_DIR" 2>/dev/null || true

    autostart_bool="false"
    if [ "$autostart" = "true" ]; then autostart_bool="true"; fi

    notif_bool="true"
    if [ "$notifications" = "false" ]; then notif_bool="false"; fi

    cat << EOF > "$ALBUS_CONFIG_FILE"
{
  "mode": "$mode",
  "dns": "$dns",
  "custom_url": "$custom_url",
  "custom_primary": "$custom_primary",
  "custom_secondary": "$custom_secondary",
  "whitelist": "$whitelist",
  "autostart": $autostart_bool,
  "notifications": $notif_bool
}
EOF
    echo '{"saved":true}'
    ;;

  set-autostart)
    enable="${1:-true}"
    mkdir -p "$ALBUS_AUTOSTART_DIR" 2>/dev/null || true
    if [ "$enable" = "true" ]; then
      cat << EOF > "$ALBUS_AUTOSTART_FILE"
[Desktop Entry]
Type=Application
Name=Albus Anti-DPI
Comment=Deep Packet Inspection evasion background daemon
Exec=albus start
Hidden=false
NoDisplay=true
X-GNOME-Autostart-enabled=true
EOF
      echo '{"autostart":true}'
    else
      rm -f "$ALBUS_AUTOSTART_FILE" 2>/dev/null || true
      echo '{"autostart":false}'
    fi
    ;;

  purge-cache)
    if [ -f "$ALBUS_USER_CONFIG_DIR/stats.json" ]; then
      rm -f "$ALBUS_USER_CONFIG_DIR/stats.json" 2>/dev/null || true
    fi
    echo '{"purged":true}'
    ;;

  status)
    binary=$(resolve_binary)
    if [ -x "$binary" ]; then
      out=$("$binary" --status 2>/dev/null || true)
      if [ -n "$out" ] && [ "$out" != '{"running":false}' ]; then
        echo "$out"
        exit 0
      fi
    fi
    if [ -S "$ALBUS_SOCKET" ] && command -v socat >/dev/null 2>&1; then
      out=$(echo "STATUS" | socat -t 0.3 - "UNIX-CONNECT:$ALBUS_SOCKET" 2>/dev/null || true)
      if [ -n "$out" ]; then
        echo "$out"
        exit 0
      fi
    fi
    echo '{"running":false}'
    ;;

  diagnose)
    binary=$(resolve_binary)
    if [ -x "$binary" ]; then
      out=$("$binary" --diagnose 2>/dev/null || true)
      if [ -n "$out" ]; then
        echo "$out"
        exit 0
      fi
    fi
    echo '{"success":false,"error":"daemon not reachable"}'
    ;;

  notify-evasion)
    target="${1:-unknown}"
    if command -v notify-send >/dev/null 2>&1; then
      notify-send -a "Albus" -i "security-high" "DPI Bypassed" "Secured connection to $target" 2>/dev/null || true
    fi
    ;;

  check-core)
    binary=$(resolve_binary)
    if [ -n "$binary" ] && [ -x "$binary" ]; then
      echo '{"ready":true,"installed":true}'
    else
      echo '{"ready":false,"installed":false}'
    fi
    ;;

  setup-download|download-core)
    mkdir -p "$project_dir/bin"
    if [ -f "$project_dir/bin/albus-core" ] && [ -x "$project_dir/bin/albus-core" ]; then
      echo '{"success":true,"version":"ready"}'
    elif [ -f "$project_dir/core/target/release/albus-core" ] && [ -x "$project_dir/core/target/release/albus-core" ]; then
      cp "$project_dir/core/target/release/albus-core" "$project_dir/bin/albus-core" 2>/dev/null || true
      chmod +x "$project_dir/bin/albus-core" 2>/dev/null || true
      echo '{"success":true,"version":"built"}'
    else
      echo '{"success":false,"error":"binary not available"}'
    fi
    ;;

  setup-compile)
    if command -v cargo >/dev/null 2>&1 && [ -d "$project_dir/core" ]; then
      if cargo build --release --manifest-path "$project_dir/core/Cargo.toml" >/dev/null 2>&1; then
        mkdir -p "$project_dir/bin" 2>/dev/null || true
        cp "$project_dir/core/target/release/albus-core" "$project_dir/bin/albus-core" 2>/dev/null || true
        chmod +x "$project_dir/bin/albus-core" 2>/dev/null || true
        echo '{"success":true}'
      else
        echo '{"success":false,"error":"cargo build failed"}'
      fi
    else
      echo '{"success":false,"error":"cargo compiler not found"}'
    fi
    ;;

  export-profile)
    export_file="$HOME/albus-profile.json"
    if [ -f "$ALBUS_CONFIG_FILE" ]; then
      cp "$ALBUS_CONFIG_FILE" "$export_file"
      echo "{\"exported\":true,\"file\":\"$export_file\"}"
    else
      echo "{\"exported\":false,\"error\":\"no config found\"}"
    fi
    ;;

  import-profile)
    import_file="$HOME/albus-profile.json"
    if [ -f "$import_file" ]; then
      mkdir -p "$ALBUS_USER_CONFIG_DIR" 2>/dev/null || true
      cp "$import_file" "$ALBUS_CONFIG_FILE"
      echo "{\"imported\":true,\"file\":\"$import_file\"}"
    else
      echo "{\"imported\":false,\"error\":\"$import_file not found\"}"
    fi
    ;;

  start)
    arg_mode="${1:-}"
    arg_dns="${2:-}"
    arg_bootstrap="${3:-}"
    arg_whitelist="${4:-}"

    mode="${arg_mode:-auto}"
    dns="${arg_dns:-quad9}"
    bootstrap="$arg_bootstrap"
    whitelist="$arg_whitelist"

    # If parameters are not explicitly provided via CLI, load saved preferences from config.json
    if [ -f "$ALBUS_CONFIG_FILE" ]; then
      cfg_mode=$(grep -o '"mode": *"[^"]*"' "$ALBUS_CONFIG_FILE" 2>/dev/null | awk -F'"' '{print $4}' || true)
      cfg_dns=$(grep -o '"dns": *"[^"]*"' "$ALBUS_CONFIG_FILE" 2>/dev/null | awk -F'"' '{print $4}' || true)
      cfg_url=$(grep -o '"custom_url": *"[^"]*"' "$ALBUS_CONFIG_FILE" 2>/dev/null | awk -F'"' '{print $4}' || true)
      cfg_p=$(grep -o '"custom_primary": *"[^"]*"' "$ALBUS_CONFIG_FILE" 2>/dev/null | awk -F'"' '{print $4}' || true)
      cfg_s=$(grep -o '"custom_secondary": *"[^"]*"' "$ALBUS_CONFIG_FILE" 2>/dev/null | awk -F'"' '{print $4}' || true)
      cfg_wl=$(grep -o '"whitelist": *"[^"]*"' "$ALBUS_CONFIG_FILE" 2>/dev/null | awk -F'"' '{print $4}' || true)

      if [ -z "$arg_mode" ] && [ -n "$cfg_mode" ]; then
        mode="$cfg_mode"
      fi
      if [ -z "$arg_dns" ] && [ -n "$cfg_dns" ]; then
        if [ "$cfg_dns" = "custom" ] && [ -n "$cfg_url" ]; then
          dns="$cfg_url"
        else
          dns="$cfg_dns"
        fi
      fi
      if [ -z "$arg_bootstrap" ]; then
        if [ -n "$cfg_p" ] && [ -n "$cfg_s" ]; then
          bootstrap="$cfg_p,$cfg_s"
        elif [ -n "$cfg_p" ]; then
          bootstrap="$cfg_p"
        fi
      fi
      if [ -z "$arg_whitelist" ] && [ -n "$cfg_wl" ]; then
        whitelist="$cfg_wl"
      fi
    fi

    binary=$(resolve_binary)
    if [ -z "$binary" ] || [ ! -x "$binary" ]; then
      if [ -d "$project_dir/core" ] && command -v cargo >/dev/null 2>&1; then
        cargo build --release --manifest-path "$project_dir/core/Cargo.toml" >/dev/null 2>&1 || true
        binary=$(resolve_binary)
      fi
    fi

    exec_privileged start "$mode" "$dns" "$bootstrap" "$whitelist" "$binary"
    ;;

  stop)
    exec_privileged stop
    rm -f "$HOME/.config/environment.d/99-albus-proxy.conf" 2>/dev/null || true
    if command -v gsettings >/dev/null 2>&1; then
      gsettings reset-recursively org.gnome.system.proxy 2>/dev/null || true
    fi
    if command -v systemctl >/dev/null 2>&1; then
      systemctl --user unset-environment all_proxy ALL_PROXY http_proxy HTTP_PROXY https_proxy HTTPS_PROXY ftp_proxy FTP_PROXY 2>/dev/null || true
      systemctl --user daemon-reexec 2>/dev/null || true
    fi
    ;;

  restart)
    $0 stop
    sleep 0.3
    $0 start "$@"
    ;;

  fix-network|repair)
    exec_privileged fix-network
    rm -f "$HOME/.config/environment.d/99-albus-proxy.conf" 2>/dev/null || true
    if command -v gsettings >/dev/null 2>&1; then
      gsettings reset-recursively org.gnome.system.proxy 2>/dev/null || true
    fi
    if command -v systemctl >/dev/null 2>&1; then
      systemctl --user unset-environment all_proxy ALL_PROXY http_proxy HTTP_PROXY https_proxy HTTPS_PROXY ftp_proxy FTP_PROXY 2>/dev/null || true
      systemctl --user daemon-reexec 2>/dev/null || true
    fi
    ;;

  logs)
    if [ -f "$ALBUS_LOG_FILE" ]; then
      cat "$ALBUS_LOG_FILE"
    elif [ -f "/tmp/albus.log" ]; then
      cat "/tmp/albus.log"
    else
      echo "No log file found at $ALBUS_LOG_FILE"
    fi
    ;;

  help|--help|-h)
    echo -e "${c_bold}${c_magenta}ALBUS ANTI-DPI${c_reset} ${c_dim}(Arch Linux Edition)${c_reset}"
    echo ""
    echo -e "${c_bold}USAGE:${c_reset}"
    echo "  albus start [mode] [dns] [bootstraps] [whitelist]"
    echo "  albus stop"
    echo "  albus restart"
    echo "  albus status"
    echo "  albus diagnose"
    echo "  albus repair"
    echo "  albus logs"
    ;;

  version|--version|-v)
    echo "Albus Anti-DPI v1.4.0"
    ;;

  *)
    echo "Unknown command: $cmd"
    echo "Run 'albus help' for usage."
    exit 1
    ;;
esac
