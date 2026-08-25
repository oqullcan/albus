#!/bin/bash
# albus seamless daemon manager with autostart, whitelist persistence, profiles, cache purge & notifications

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(dirname "$script_dir")"
if [ -x "/usr/lib/albus/albus-core" ]; then
  binary="/usr/lib/albus/albus-core"
elif [ -x "$project_dir/bin/albus-core" ]; then
  binary="$project_dir/bin/albus-core"
elif [ -x "$project_dir/core/target/release/albus-core" ]; then
  binary="$project_dir/core/target/release/albus-core"
elif [ -x "/usr/bin/albus-core" ]; then
  binary="/usr/bin/albus-core"
else
  binary="$project_dir/bin/albus-core"
fi

pid_file="/tmp/albus-daemon.pid"

log_file="/tmp/albus.log"
config_dir="$HOME/.config/albus"
config_file="$config_dir/config.json"
autostart_dir="$HOME/.config/autostart"
autostart_file="$autostart_dir/albus.desktop"

mkdir -p "$config_dir" "$autostart_dir"

if [ -f "$HOME/.config/environment.d/99-albus-proxy.conf" ]; then
  rm -f "$HOME/.config/environment.d/99-albus-proxy.conf"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl --user unset-environment all_proxy ALL_PROXY http_proxy HTTP_PROXY https_proxy HTTPS_PROXY 2>/dev/null || true
  fi
fi


action="${1:-status}"
mode="${2:-}"
dns="${3:-}"
bootstrap="${4:-}"
whitelist="${5:-}"

get_latest_version() {
  local tag
  tag=$(curl -sSL --connect-timeout 2 "https://api.github.com/repos/oqullcan/albus/releases/latest" 2>/dev/null | grep -o '"tag_name": *"[^"]*"' | cut -d'"' -f4 || true)
  if [ -z "$tag" ]; then
    tag=$(curl -sSL --connect-timeout 2 "https://api.github.com/repos/oqullcan/albus/tags" 2>/dev/null | grep -o '"name": *"[^"]*"' | head -n 1 | cut -d'"' -f4 || echo "v1.0.0")
  fi
  if [ -z "$tag" ]; then tag="v1.0.0"; fi
  echo "$tag"
}

load_config() {

  if [ -f "$config_file" ]; then
    cat "$config_file"
  else
    echo '{"mode":"auto","dns":"quad9","custom_url":"","custom_primary":"","custom_secondary":"","whitelist":"","autostart":false,"notifications":false}'
  fi
}

save_config() {
  local s_mode="${1:-auto}"
  local s_dns="${2:-quad9}"
  local s_url="${3:-}"
  local s_p="${4:-}"
  local s_s="${5:-}"
  local s_w="${6:-}"
  local s_auto="${7:-false}"
  local s_notif="${8:-false}"

  s_mode=$(echo "$s_mode" | tr -d '\r\n' | xargs)
  s_dns=$(echo "$s_dns" | tr -d '\r\n' | xargs)
  s_url=$(echo "$s_url" | tr -d '\r\n' | xargs)
  s_p=$(echo "$s_p" | tr -d '\r\n' | xargs)
  s_s=$(echo "$s_s" | tr -d '\r\n' | xargs)
  s_w=$(echo "$s_w" | tr -d '\r\n' | xargs)
  s_auto=$(echo "$s_auto" | tr -d '\r\n' | xargs)
  s_notif=$(echo "$s_notif" | tr -d '\r\n' | xargs)

  cat << JSON > "$config_file"
{
  "mode": "$s_mode",
  "dns": "$s_dns",
  "custom_url": "$s_url",
  "custom_primary": "$s_p",
  "custom_secondary": "$s_s",
  "whitelist": "$s_w",
  "autostart": $s_auto,
  "notifications": $s_notif
}
JSON
}

exec_privileged() {
  local helper="$script_dir/albus-service.sh"
  if [ -x "/usr/lib/albus/albus-service.sh" ]; then
    helper="/usr/lib/albus/albus-service.sh"
  fi

  if [ "$(id -u)" -eq 0 ]; then
    "$script_dir/albus-service.sh" "$@"
  elif [ -t 0 ] && command -v sudo >/dev/null 2>&1; then
    sudo "$script_dir/albus-service.sh" "$@"
  elif command -v pkexec >/dev/null 2>&1; then
    pkexec "$helper" "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$script_dir/albus-service.sh" "$@"
  else
    echo "{\"running\":false,\"error\":\"Neither pkexec nor sudo found\"}"
    exit 1
  fi
}





case "$action" in

  get-latest-version)
    get_latest_version
    exit 0
    ;;

  check-core)
    installed=false
    if [ -x "/usr/lib/albus/albus-core" ] || [ -x "$project_dir/bin/albus-core" ] || [ -x "$project_dir/core/target/release/albus-core" ]; then
      installed=true
    fi
    has_cargo=false
    if command -v cargo >/dev/null 2>&1; then
      has_cargo=true
    fi
    ver=$(get_latest_version)
    echo "{\"installed\":$installed,\"has_cargo\":$has_cargo,\"latest_version\":\"$ver\"}"
    exit 0
    ;;

  setup-download)
    ver=$(get_latest_version)
    mkdir -p "$project_dir/bin"
    downloaded=false
    if curl -sSL "https://raw.githubusercontent.com/oqullcan/albus/master/bin/albus-core" -o "$project_dir/bin/albus-core" 2>/dev/null; then
      downloaded=true
    elif curl -sSL "https://github.com/oqullcan/albus/releases/download/${ver}/albus-core" -o "$project_dir/bin/albus-core" 2>/dev/null; then
      downloaded=true
    fi

    if [ -s "$project_dir/bin/albus-core" ]; then
      chmod +x "$project_dir/bin/albus-core"
      echo "{\"success\":true,\"version\":\"$ver\"}"
    else
      echo "{\"success\":false,\"error\":\"Download failed. Check internet connection.\"}"
    fi
    exit 0
    ;;

  setup-compile)
    if command -v cargo >/dev/null 2>&1 && [ -f "$project_dir/core/Cargo.toml" ]; then
      if cargo build --release --manifest-path "$project_dir/core/Cargo.toml" >/dev/null 2>&1; then
        mkdir -p "$project_dir/bin"
        cp "$project_dir/core/target/release/albus-core" "$project_dir/bin/albus-core" 2>/dev/null || true
        echo "{\"success\":true,\"version\":\"compiled\"}"
      else
        echo "{\"success\":false,\"error\":\"Cargo compilation failed.\"}"
      fi
    else
      echo "{\"success\":false,\"error\":\"Cargo is not installed.\"}"
    fi
    exit 0
    ;;


  get-config)

    load_config
    exit 0
    ;;

  save-config)
    save_config "${2:-auto}" "${3:-quad9}" "${4:-}" "${5:-}" "${6:-}" "${7:-}" "${8:-false}" "${9:-false}"
    echo "{\"saved\":true}"
    exit 0
    ;;

  purge-cache)
    resolvectl flush-caches 2>/dev/null || true
    echo "{\"purged\":true}"
    exit 0
    ;;

  fix-network|repair)
    exec_privileged repair
    exit 0
    ;;


  export-profile)
    out_file="${2:-}"
    if [ -z "$out_file" ]; then
      if command -v zenity >/dev/null 2>&1; then
        out_file=$(zenity --file-selection --save --confirm-overwrite --filename="$HOME/albus-profile.json" --file-filter="JSON Profile (*.json) | *.json" --title="Export Albus Profile" 2>/dev/null || true)
      elif command -v kdialog >/dev/null 2>&1; then
        out_file=$(kdialog --getsavefilename "$HOME/albus-profile.json" "*.json" --title "Export Albus Profile" 2>/dev/null || true)
      else
        out_file="$HOME/albus-profile.json"
      fi
    fi

    if [ -n "$out_file" ]; then
      cp "$config_file" "$out_file" 2>/dev/null || true
      echo "{\"exported\":true,\"file\":\"$out_file\"}"
      exit 0
    else
      echo "{\"exported\":false,\"error\":\"cancelled\"}"
      exit 0
    fi
    ;;

  import-profile)
    in_file="${2:-}"
    if [ -z "$in_file" ]; then
      if command -v zenity >/dev/null 2>&1; then
        in_file=$(zenity --file-selection --file-filter="JSON Profile (*.json) | *.json" --title="Select Albus Profile to Import" 2>/dev/null || true)
      elif command -v kdialog >/dev/null 2>&1; then
        in_file=$(kdialog --getopenfilename "$HOME" "*.json" --title "Select Albus Profile to Import" 2>/dev/null || true)
      else
        in_file="$HOME/albus-profile.json"
      fi
    fi

    if [ -n "$in_file" ] && [ -f "$in_file" ]; then
      cp "$in_file" "$config_file"
      echo "{\"imported\":true,\"file\":\"$in_file\"}"
      exit 0
    else
      echo "{\"imported\":false,\"error\":\"cancelled\"}"
      exit 0
    fi
    ;;

  notify-evasion)
    target="${2:-domain}"
    if command -v notify-send >/dev/null 2>&1; then
      notify-send "Albus Anti-DPI" "Censorship filter bypassed on $target" -a "Albus" 2>/dev/null || true
    fi
    echo "{\"notified\":true}"
    exit 0
    ;;



  set-autostart)
    state="${2:-false}"
    if [ "$state" = "true" ]; then
      cat << DESKTOP > "$autostart_file"
[Desktop Entry]
Type=Application
Name=Albus Anti-DPI
Exec=$script_dir/albus-daemon.sh start
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
DESKTOP
    else
      rm -f "$autostart_file"
    fi
    echo "{\"autostart\":$state}"
    exit 0
    ;;

  diagnose)
    if [ -x "$binary" ]; then
      out=$("$binary" --diagnose 2>/dev/null || true)
      if [ -n "$out" ]; then
        echo "$out"
        exit 0
      fi
    fi
    echo '{"error":"Diagnostic failed"}'
    exit 1
    ;;

  start)
    cfg=$(load_config)
    if [ -z "$mode" ]; then
      mode=$(echo "$cfg" | grep -o '"mode": *"[^"]*"' | cut -d'"' -f4 || echo "auto")
    fi
    if [ -z "$dns" ]; then
      raw_dns=$(echo "$cfg" | grep -o '"dns": *"[^"]*"' | cut -d'"' -f4 || echo "quad9")
      if [ "$raw_dns" = "custom" ]; then
        custom_url=$(echo "$cfg" | grep -o '"custom_url": *"[^"]*"' | cut -d'"' -f4 || echo "")
        if [ -n "$custom_url" ]; then
          dns="$custom_url"
        else
          dns="quad9"
        fi
      else
        dns="$raw_dns"
      fi
    fi
    if [ -z "$bootstrap" ]; then
      p_ip=$(echo "$cfg" | grep -o '"custom_primary": *"[^"]*"' | cut -d'"' -f4 || echo "")
      s_ip=$(echo "$cfg" | grep -o '"custom_secondary": *"[^"]*"' | cut -d'"' -f4 || echo "")
      if [ -n "$p_ip" ] && [ -n "$s_ip" ]; then
        bootstrap="${p_ip},${s_ip}"
      elif [ -n "$p_ip" ]; then
        bootstrap="$p_ip"
      elif [ -n "$s_ip" ]; then
        bootstrap="$s_ip"
      fi
    fi
    if [ -z "$whitelist" ]; then
      whitelist=$(echo "$cfg" | grep -o '"whitelist": *"[^"]*"' | cut -d'"' -f4 || echo "")
    fi


    mode=$(echo "$mode" | tr -d '\r\n' | xargs)
    dns=$(echo "$dns" | tr -d '\r\n' | xargs)
    bootstrap=$(echo "$bootstrap" | tr -d '\r\n' | xargs)
    whitelist=$(echo "$whitelist" | tr -d '\r\n' | xargs)

    # ensure binary is available
    if [ ! -x "$binary" ]; then
      if command -v cargo >/dev/null 2>&1 && [ -f "$project_dir/core/Cargo.toml" ]; then
        cargo build --release --manifest-path "$project_dir/core/Cargo.toml" >/dev/null 2>&1 || true
      elif command -v pkexec >/dev/null 2>&1 && command -v pacman >/dev/null 2>&1; then
        pkexec pacman -S --needed --noconfirm rust cargo 2>/dev/null || true
        if command -v cargo >/dev/null 2>&1 && [ -f "$project_dir/core/Cargo.toml" ]; then
          cargo build --release --manifest-path "$project_dir/core/Cargo.toml" >/dev/null 2>&1 || true
        fi
      fi
      if [ ! -x "$binary" ]; then
        mkdir -p "$(dirname "$binary")"
        curl -sSL "https://github.com/oqullcan/albus/releases/download/v1.0.0/albus-core" -o "$binary" 2>/dev/null && chmod +x "$binary" || true
      fi
    fi

    exec_privileged start "$mode" "$dns" "$bootstrap" "$whitelist" "$binary"



    ;;

  stop)
    exec_privileged stop
    ;;


  status)
    if [ -x "$binary" ]; then
      out=$("$binary" --status 2>/dev/null || true)
      if [ -n "$out" ] && [ "$out" != "{\"running\":false}" ]; then
        echo "$out"
        exit 0
      fi
    fi
    echo "{\"running\":false}"
    ;;

  *)
    echo "usage: albus-daemon.sh {start|stop|status|diagnose|fix-network|get-config|save-config|export-profile|import-profile|purge-cache|notify-evasion}"
    exit 1
    ;;
esac
