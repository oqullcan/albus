#!/bin/bash
# system and desktop proxy configuration helper

action="${1:-disable}"
host="${2:-127.0.0.1}"
port="${3:-1080}"
env_dir="$HOME/.config/environment.d"
env_file="$env_dir/99-albus-proxy.conf"

mkdir -p "$env_dir"

if [ "$action" = "enable" ]; then
  # configure standard gnome / gtk desktop proxy settings
  if command -v gsettings >/dev/null 2>&1; then
    gsettings set org.gnome.system.proxy mode 'manual' 2>/dev/null || true
    gsettings set org.gnome.system.proxy.http host "$host" 2>/dev/null || true
    gsettings set org.gnome.system.proxy.http port "$port" 2>/dev/null || true
    gsettings set org.gnome.system.proxy.https host "$host" 2>/dev/null || true
    gsettings set org.gnome.system.proxy.https port "$port" 2>/dev/null || true
    gsettings set org.gnome.system.proxy.socks host "$host" 2>/dev/null || true
    gsettings set org.gnome.system.proxy.socks port "$port" 2>/dev/null || true
  fi

  # write standard user session environment
  cat << ENV_EOF > "$env_file"
all_proxy=socks5://$host:$port
ALL_PROXY=socks5://$host:$port
http_proxy=http://$host:$port
HTTP_PROXY=http://$host:$port
https_proxy=http://$host:$port
HTTPS_PROXY=http://$host:$port
ENV_EOF

  if command -v systemctl >/dev/null 2>&1; then
    systemctl --user import-environment all_proxy ALL_PROXY http_proxy HTTP_PROXY https_proxy HTTPS_PROXY 2>/dev/null || true
  fi

  echo "{\"proxy\":\"enabled\"}"
else
  # reset desktop proxy settings
  if command -v gsettings >/dev/null 2>&1; then
    gsettings set org.gnome.system.proxy mode 'none' 2>/dev/null || true
  fi

  # remove environment file
  rm -f "$env_file"

  if command -v systemctl >/dev/null 2>&1; then
    systemctl --user unset-environment all_proxy ALL_PROXY http_proxy HTTP_PROXY https_proxy HTTPS_PROXY 2>/dev/null || true
  fi

  echo "{\"proxy\":\"disabled\"}"
fi
