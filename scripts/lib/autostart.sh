#!/bin/bash
# albus autostart management module

set -u

autostart_set() {
  local enable="${1:-true}"
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
}
