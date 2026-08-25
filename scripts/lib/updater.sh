#!/bin/bash
# albus system synchronizer & binary updater module

set -u

# Synchronize scripts and binary into /usr/lib/albus
system_sync() {
  local binary="${1:-}"

  if [ "$(id -u)" -ne 0 ]; then
    return 0
  fi

  mkdir -p "$ALBUS_LIB_DIR/lib" "/usr/share/polkit-1/actions" 2>/dev/null || true

  if [ -n "$binary" ] && [ -x "$binary" ]; then
    install -m755 "$binary" "$ALBUS_LIB_DIR/albus-core" 2>/dev/null || true
  fi

  # Locate source directory
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
      for f in "$src_dir/lib/"*.sh; do
        if [ -f "$f" ]; then
          install -m755 "$f" "$ALBUS_LIB_DIR/lib/$(basename "$f")" 2>/dev/null || true
        fi
      done
    fi
  fi
}
