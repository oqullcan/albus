#!/bin/bash
# albus one-line installer and build script for omarchy (Pure Rust Architecture)

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "\033[38;2;203;166;247m\033[1mALBUS ANTI-DPI INSTALLER\033[0m \033[2m(Pure Rust & Omarchy)\033[0m"
echo ""

# 1. Resolve or compile release binary
if [ -x "$script_dir/bin/albus" ]; then
  binary="$script_dir/bin/albus"
  echo -e "\033[38;2;166;227;161m> Found ready pre-compiled binary (bin/albus).\033[0m"
elif command -v cargo >/dev/null 2>&1; then
  echo -e "\033[38;2;137;180;250m> Compiling unified release binary with cargo...\033[0m"
  cargo build --release --manifest-path "$script_dir/core/Cargo.toml"
  binary="$script_dir/core/target/release/albus"
  mkdir -p "$script_dir/bin"
  cp "$binary" "$script_dir/bin/albus"
  cp "$binary" "$script_dir/bin/albus-core"
else
  echo -e "\033[38;2;243;139;168mError: cargo not found and no precompiled binary available.\033[0m"
  exit 1
fi

# Clean up any legacy proxy environment configuration
rm -f "$HOME/.config/environment.d/99-albus-proxy.conf" 2>/dev/null || true
if command -v systemctl >/dev/null 2>&1; then
  systemctl --user unset-environment all_proxy ALL_PROXY http_proxy HTTP_PROXY https_proxy HTTPS_PROXY 2>/dev/null || true
fi
if command -v gsettings >/dev/null 2>&1; then
  gsettings set org.gnome.system.proxy mode 'none' 2>/dev/null || true
fi

# 2. Install user CLI binary to ~/.local/bin/albus
mkdir -p "$HOME/.local/bin"
install -m755 "$binary" "$HOME/.local/bin/albus"
install -m755 "$binary" "$HOME/.local/bin/albus-core"

# 3. Link plugin to omarchy directory
omarchy_plugin_dir="$HOME/.config/omarchy/plugins/io.github.oqullcan.albus"
mkdir -p "$(dirname "$omarchy_plugin_dir")"
rm -rf "$omarchy_plugin_dir"
ln -s "$script_dir" "$omarchy_plugin_dir"

# 4. Install system binaries, systemd service, and polkit policy
echo -e "\033[38;2;137;180;250m> Installing system binaries and security policies...\033[0m"
if [ "$(id -u)" -eq 0 ]; then
  mkdir -p /usr/lib/albus /usr/bin /usr/share/polkit-1/actions /etc/systemd/system
  install -m755 "$binary" /usr/lib/albus/albus
  install -m755 "$binary" /usr/lib/albus/albus-core
  install -m755 "$binary" /usr/bin/albus
  install -m755 "$binary" /usr/bin/albus-core
  install -m644 "$script_dir/systemd/albus.service" /etc/systemd/system/albus.service
  install -m644 "$script_dir/polkit/io.github.oqullcan.albus.policy" /usr/share/polkit-1/actions/io.github.oqullcan.albus.policy
  systemctl daemon-reload 2>/dev/null || true
elif command -v pkexec >/dev/null 2>&1; then
  pkexec bash -c "
    mkdir -p /usr/lib/albus /usr/bin /usr/share/polkit-1/actions /etc/systemd/system && \
    install -m755 '$binary' /usr/lib/albus/albus && \
    install -m755 '$binary' /usr/lib/albus/albus-core && \
    install -m755 '$binary' /usr/bin/albus && \
    install -m755 '$binary' /usr/bin/albus-core && \
    install -m644 '$script_dir/systemd/albus.service' /etc/systemd/system/albus.service && \
    install -m644 '$script_dir/polkit/io.github.oqullcan.albus.policy' /usr/share/polkit-1/actions/io.github.oqullcan.albus.policy && \
    systemctl daemon-reload 2>/dev/null || true
  "
elif command -v sudo >/dev/null 2>&1; then
  sudo mkdir -p /usr/lib/albus /usr/bin /usr/share/polkit-1/actions /etc/systemd/system
  sudo install -m755 "$binary" /usr/lib/albus/albus
  sudo install -m755 "$binary" /usr/lib/albus/albus-core
  sudo install -m755 "$binary" /usr/bin/albus
  sudo install -m755 "$binary" /usr/bin/albus-core
  sudo install -m644 "$script_dir/systemd/albus.service" /etc/systemd/system/albus.service
  sudo install -m644 "$script_dir/polkit/io.github.oqullcan.albus.policy" /usr/share/polkit-1/actions/io.github.oqullcan.albus.policy
  sudo systemctl daemon-reload 2>/dev/null || true
fi

echo -e "\033[38;2;166;227;161m[OK] Pure Rust installation complete!\033[0m"
echo -e "Run \033[1m'albus status'\033[0m or open the Omarchy panel to start."
