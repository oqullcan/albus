#!/bin/bash
# albus configuration management module

set -u

config_get() {
  if [ -f "$ALBUS_CONFIG_FILE" ]; then
    cat "$ALBUS_CONFIG_FILE"
  else
    echo '{"mode":"auto","dns":"quad9","custom_url":"","custom_primary":"","custom_secondary":"","whitelist":"","autostart":false,"notifications":true}'
  fi
}

config_save() {
  local mode="${1:-auto}"
  local dns="${2:-quad9}"
  local custom_url="${3:-}"
  local custom_primary="${4:-}"
  local custom_secondary="${5:-}"
  local whitelist="${6:-}"
  local autostart="${7:-false}"
  local notifications="${8:-true}"

  mkdir -p "$ALBUS_USER_CONFIG_DIR" 2>/dev/null || true

  local autostart_bool="false"
  if [ "$autostart" = "true" ]; then autostart_bool="true"; fi

  local notif_bool="true"
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
}
