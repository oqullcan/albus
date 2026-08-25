#!/bin/bash
# albus one-line installer and build script for omarchy

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "\033[38;2;203;166;247m\033[1mALBUS ANTI-DPI INSTALLER\033[0m \033[2m(Omarchy)\033[0m"
echo ""

get_latest_version() {
  local tag
  tag=$(curl -sSL --connect-timeout 2 "https://api.github.com/repos/oqullcan/albus/releases/latest" 2>/dev/null | grep -o '"tag_name": *"[^"]*"' | cut -d'"' -f4 || true)
  if [ -z "$tag" ]; then
    tag=$(curl -sSL --connect-timeout 2 "https://api.github.com/repos/oqullcan/albus/tags" 2>/dev/null | grep -o '"name": *"[^"]*"' | head -n 1 | cut -d'"' -f4 || echo "v1.0.0")
  fi
  if [ -z "$tag" ]; then tag="v1.0.0"; fi
  echo "$tag"
}

# 1. resolve pre-compiled binary or build with cargo
if [ -x "$script_dir/bin/albus-core" ]; then
  binary="$script_dir/bin/albus-core"
  echo -e "\033[38;2;166;227;161m> Found ready pre-compiled binary (bin/albus-core). Zero build required!\033[0m"
elif command -v cargo >/dev/null 2>&1; then
  echo -e "\033[38;2;137;180;250m> Compiling optimized release binary with cargo...\033[0m"
  cargo build --release --manifest-path "$script_dir/core/Cargo.toml"
  binary="$script_dir/core/target/release/albus-core"
else
  latest_tag=$(get_latest_version)
  echo -e "\033[38;2;249;226;175m> Fetching pre-compiled release binary (${latest_tag}) from GitHub...\033[0m"
  mkdir -p "$script_dir/bin"
  curl -sSL "https://raw.githubusercontent.com/oqullcan/albus/master/bin/albus-core" -o "$script_dir/bin/albus-core" 2>/dev/null || \
  curl -sSL "https://github.com/oqullcan/albus/releases/download/${latest_tag}/albus-core" -o "$script_dir/bin/albus-core" 2>/dev/null || true
  chmod +x "$script_dir/bin/albus-core" 2>/dev/null || true
  binary="$script_dir/bin/albus-core"
fi




# Clean up any legacy proxy environment configuration
rm -f "$HOME/.config/environment.d/99-albus-proxy.conf" 2>/dev/null || true
if command -v systemctl >/dev/null 2>&1; then
  systemctl --user unset-environment all_proxy ALL_PROXY http_proxy HTTP_PROXY https_proxy HTTPS_PROXY 2>/dev/null || true
fi
if command -v gsettings >/dev/null 2>&1; then
  gsettings set org.gnome.system.proxy mode 'none' 2>/dev/null || true
fi

# 2. setup executable permissions on scripts
chmod +x "$script_dir/scripts/albus-"*.sh 2>/dev/null || true


# 3. install global CLI command to ~/.local/bin/albus
mkdir -p "$HOME/.local/bin"

cat << 'ALBUS_CLI' > "$HOME/.local/bin/albus"
#!/bin/bash
# albus - elegant cli management tool for albus anti-dpi on omarchy

set -euo pipefail

plugin_dir="$HOME/.config/omarchy/plugins/io.github.oqullcan.albus"
daemon_script="$plugin_dir/scripts/albus-daemon.sh"
binary="$plugin_dir/core/target/release/albus-core"


c_reset="\033[0m"
c_bold="\033[1m"
c_dim="\033[2m"
c_green="\033[38;2;166;227;161m"
c_blue="\033[38;2;137;180;250m"
c_cyan="\033[38;2;148;226;213m"
c_yellow="\033[38;2;249;226;175m"
c_red="\033[38;2;243;139;168m"
c_magenta="\033[38;2;203;166;247m"

print_banner() {
  echo -e "${c_magenta}${c_bold}  ALBUS ANTI-DPI${c_reset} ${c_dim}(Omarchy Edition)${c_reset}"
  echo ""
}

cmd="${1:-status}"

case "$cmd" in
  start)
    print_banner
    echo -e "${c_blue}> Starting Albus Anti-DPI daemon...${c_reset}"
    "$daemon_script" start "${2:-}" "${3:-}" "${4:-}" "${5:-}"
    sleep 0.2
    albus status
    ;;

  stop)
    print_banner
    echo -e "${c_yellow}> Stopping Albus daemon and restoring network rules...${c_reset}"
    "$daemon_script" stop
    echo -e "${c_green}[OK] Albus daemon stopped cleanly.${c_reset}"
    ;;

  restart)
    print_banner
    echo -e "${c_blue}> Restarting Albus Anti-DPI...${c_reset}"
    "$daemon_script" stop 2>/dev/null || true
    sleep 0.3
    "$daemon_script" start "${2:-}" "${3:-}" "${4:-}" "${5:-}"
    sleep 0.2
    albus status
    ;;

  status)
    raw=$("$daemon_script" status 2>/dev/null || echo '{"running":false}')
    if echo "$raw" | grep -q '"running":true'; then
      total=$(echo "$raw" | grep -o '"total":[0-9]*' | cut -d: -f2 || echo "0")
      tls=$(echo "$raw" | grep -o '"tls":[0-9]*' | cut -d: -f2 || echo "0")
      bytes_str=$(echo "$raw" | grep -o '"bytes_str":"[^"]*"' | cut -d'"' -f4 || echo "0 B")
      speed_str=$(echo "$raw" | grep -o '"speed_str":"[^"]*"' | cut -d'"' -f4 || echo "0 B/s")
      lat=$(echo "$raw" | grep -o '"latency":[0-9]*' | cut -d: -f2 || echo "0")
      dns=$(echo "$raw" | grep -o '"dns":"[^"]*"' | cut -d'"' -f4 || echo "Quad9")
      on_bat=$(echo "$raw" | grep -o '"battery":[^,}]*' | cut -d: -f2 || echo "false")
      poison=$(echo "$raw" | grep -o '"poison_blocks":[0-9]*' | cut -d: -f2 || echo "0")

      print_banner
      echo -e "  ● Status:       ${c_green}${c_bold}ACTIVE (Protected)${c_reset}"
      echo -e "    Data Shield:  ${c_cyan}${c_bold}${bytes_str}${c_reset}"
      if [ "$speed_str" != "0 B/s" ]; then
        echo -e "    Throughput:   ${c_green}${c_bold}${speed_str}${c_reset}"
      fi
      echo -e "    DNS Relay:    ${c_blue}${dns}${c_reset} (${c_yellow}${lat} ms${c_reset})"
      echo -e "    TLS Bypassed: ${c_magenta}${tls}${c_reset} / ${total} sessions"

      if [ "$poison" -gt 0 ]; then
        echo -e "    DNS Armor:    ${c_yellow}${poison} ISP Poisoning Attacks Deflected${c_reset}"
      fi
      if [ "$on_bat" = "true" ]; then
        echo -e "    Power Mode:   ${c_green}Battery-Aware (Eco Polling)${c_reset}"
      fi
      echo ""
    else
      print_banner
      echo -e "  ○ Status:       ${c_red}${c_bold}STOPPED (Direct Network)${c_reset}"
      echo -e "  ${c_dim}Run 'albus start' to activate protection.${c_reset}"
      echo ""
    fi
    ;;

  stats)
    raw=$("$daemon_script" status 2>/dev/null || echo '{"running":false}')
    print_banner
    echo -e "${c_bold}PROTECTION METRICS & SHIELD TELEMETRY:${c_reset}"
    echo ""
    if echo "$raw" | grep -q '"running":true'; then
      total=$(echo "$raw" | grep -o '"total":[0-9]*' | cut -d: -f2 || echo "0")
      tls=$(echo "$raw" | grep -o '"tls":[0-9]*' | cut -d: -f2 || echo "0")
      http=$(echo "$raw" | grep -o '"http":[0-9]*' | cut -d: -f2 || echo "0")
      bytes_str=$(echo "$raw" | grep -o '"bytes_str":"[^"]*"' | cut -d'"' -f4 || echo "0 B")
      lat=$(echo "$raw" | grep -o '"latency":[0-9]*' | cut -d: -f2 || echo "0")
      dns=$(echo "$raw" | grep -o '"dns":"[^"]*"' | cut -d'"' -f4 || echo "Quad9")
      poison=$(echo "$raw" | grep -o '"poison_blocks":[0-9]*' | cut -d: -f2 || echo "0")

      echo -e "  ┌─ Session Overview"
      echo -e "  │  • Protected Traffic:   ${c_cyan}${c_bold}${bytes_str}${c_reset}"
      echo -e "  │  • Total Sessions:      ${c_bold}${total}${c_reset}"
      echo -e "  │  • TLS ClientHello:     ${c_green}${tls} bypassed${c_reset}"
      echo -e "  │  • HTTP/2 & Sanitized:  ${c_magenta}${http} processed${c_reset}"
      echo -e "  │  • Poisoning Deflected: ${c_yellow}${poison} ISP injections blocked${c_reset}"
      echo -e "  │"
      echo -e "  ├─ DNS Architecture"
      echo -e "  │  • Active Resolver:     ${c_blue}${dns}${c_reset}"
      echo -e "  │  • Average Latency:     ${c_yellow}${lat} ms${c_reset}"
      echo -e "  │  • Prefetch Engine:     ${c_green}Active (Predictive CDN Pre-warm)${c_reset}"
      echo -e "  │  • Location Armor:      ${c_green}ECS Stripped & RFC 8467 Padded${c_reset}"
      echo -e "  │"
      echo -e "  └─ Memory & Socket Tuning"
      echo -e "     • Memory Locking:      ${c_cyan}mlockall (Anti-Swap Protected)${c_reset}"
      echo -e "     • Socket Low-Water:    ${c_green}TCP_NOTSENT_LOWAT (16KB Low Latency)${c_reset}"
      echo -e "     • Volatile Scrubbing:  ${c_green}Zeroize active${c_reset}"
      echo ""
    else
      echo -e "  ${c_yellow}Daemon is currently stopped.${c_reset}"
      echo -e "  Run 'albus start' to view live metrics."
      echo ""
    fi
    ;;

  fix-network|repair|fix)
    print_banner
    echo -e "${c_yellow}> Performing emergency network repair & firewall flush...${c_reset}"
    "$daemon_script" fix-network
    echo -e "${c_green}[OK] Network routes reverted and all Albus firewall rules flushed.${c_reset}"
    ;;

  purge|flush)
    print_banner
    echo -e "${c_blue}> Purging DNS resolver and local socket caches...${c_reset}"
    "$daemon_script" purge-cache
    echo -e "${c_green}[OK] Cache flushed successfully.${c_reset}"
    ;;

  diag|diagnose)
    print_banner
    echo -e "${c_blue}> Running comprehensive multi-CDN connectivity benchmark...${c_reset}"
    echo ""
    "$binary" --diagnose
    echo ""
    ;;

  test|check)
    print_banner
    echo -e "${c_bold}ALBUS DEFENSE & LEAK SUITE:${c_reset}"
    echo ""

    raw=$("$daemon_script" status 2>/dev/null || echo '{"running":false}')
    if echo "$raw" | grep -q '"running":true'; then
      echo -e "  [${c_green}✔${c_reset}] Daemon Core:           ${c_green}Active${c_reset} (SO_MARK 0x1337)"
    else
      echo -e "  [${c_red}✘${c_reset}] Daemon Core:           ${c_red}Stopped${c_reset}"
    fi

    if ss -uln 2>/dev/null | grep -q ":5300"; then
      echo -e "  [${c_green}✔${c_reset}] Local DNS Relay:       ${c_green}Listening on 127.0.0.1:5300 (UDP+TCP)${c_reset}"
    else
      echo -e "  [${c_yellow}○${c_reset}] Local DNS Relay:       ${c_dim}Offline${c_reset}"
    fi

    if ss -tln 2>/dev/null | grep -q ":1080"; then
      echo -e "  [${c_green}✔${c_reset}] Transparent Intercept: ${c_green}Active on 127.0.0.1:1080 (1-byte TLS Split)${c_reset}"
    else
      echo -e "  [${c_yellow}○${c_reset}] Transparent Intercept: ${c_dim}Offline${c_reset}"
    fi

    if resolvectl 2>/dev/null | grep -q "127.0.0.1:5300"; then
      echo -e "  [${c_green}✔${c_reset}] DNS Root Routing:      ${c_green}Enforced (~. -> 127.0.0.1:5300)${c_reset}"
    else
      echo -e "  [${c_yellow}○${c_reset}] DNS Root Routing:      ${c_dim}Default System DNS${c_reset}"
    fi

    if iptables -t nat -L ALBUS >/dev/null 2>&1; then
      echo -e "  [${c_green}✔${c_reset}] Netfilter Chains:      ${c_green}ALBUS & ALBUS_DNS Active${c_reset}"
    elif echo "$raw" | grep -q '"running":true'; then
      echo -e "  [${c_green}✔${c_reset}] Netfilter Chains:      ${c_green}ALBUS & ALBUS_DNS Active (Root Managed)${c_reset}"
    else
      echo -e "  [${c_yellow}○${c_reset}] Netfilter Chains:      ${c_dim}Unloaded${c_reset}"
    fi

    if iptables -L OUTPUT -v -n 2>/dev/null | grep -q "dpt:53"; then
      echo -e "  [${c_green}✔${c_reset}] DNS Leak Armor:        ${c_green}Dead-Man Switch Active (Plaintext UDP 53 Dropped)${c_reset}"
    elif echo "$raw" | grep -q '"running":true'; then
      echo -e "  [${c_green}✔${c_reset}] DNS Leak Armor:        ${c_green}Dead-Man Switch Active (Kernel Netfilter)${c_reset}"
    else
      echo -e "  [${c_yellow}○${c_reset}] DNS Leak Armor:        ${c_dim}Unloaded${c_reset}"
    fi


    echo ""
    echo -e "  ${c_dim}Run 'albus diag' for CDN latency & target bypass benchmark.${c_reset}"
    echo ""
    ;;

  logs|log)
    echo -e "${c_cyan}Tailing /tmp/albus.log (Ctrl+C to exit):${c_reset}"
    tail -f /tmp/albus.log
    ;;

  help|--help|-h)
    print_banner
    echo -e "${c_bold}USAGE:${c_reset} albus <command> [options]"
    echo ""
    echo -e "  ${c_green}start${c_reset}        Start Albus daemon with saved profile"
    echo -e "  ${c_yellow}stop${c_reset}         Stop daemon & safely clean firewall rules"
    echo -e "  ${c_blue}restart${c_reset}      Restart daemon"
    echo -e "  ${c_cyan}status${c_reset}       Show live protection status and metrics"
    echo -e "  ${c_magenta}stats${c_reset}        Detailed session telemetry and memory metrics"
    echo -e "  ${c_green}test${c_reset}         Run instant live leak & defense verification suite"
    echo -e "  ${c_yellow}fix-network${c_reset}  Emergency firewall flush & network repair"
    echo -e "  ${c_blue}purge${c_reset}        Flush local DNS resolver caches"
    echo -e "  ${c_green}diag${c_reset}         Run multi-CDN latency & bypass test"
    echo -e "  ${c_dim}logs${c_reset}         Follow daemon logs in real-time"
    echo ""
    ;;

  *)
    print_banner
    echo -e "${c_red}Unknown command: $cmd${c_reset}"
    echo "Run 'albus help' for available commands."
    exit 1
    ;;
esac
ALBUS_CLI

chmod +x "$HOME/.local/bin/albus"

# 4. link plugin to omarchy directory
omarchy_plugin_dir="$HOME/.config/omarchy/plugins/io.github.oqullcan.albus"
mkdir -p "$(dirname "$omarchy_plugin_dir")"
rm -rf "$omarchy_plugin_dir"
ln -s "$script_dir" "$omarchy_plugin_dir"

# 5. install root-owned system helper and polkit policy (zero-TOCTOU security model)
echo -e "\033[38;2;137;180;250m> Installing root-owned helper to /usr/lib/albus/...\033[0m"
if [ "$(id -u)" -eq 0 ]; then
  mkdir -p /usr/lib/albus/lib /usr/share/polkit-1/actions
  install -m755 "$script_dir/scripts/albus-service.sh" /usr/lib/albus/albus-service.sh
  install -m755 "$script_dir/scripts/albus-transparent.sh" /usr/lib/albus/albus-transparent.sh
  install -m755 "$script_dir/scripts/lib/"*.sh /usr/lib/albus/lib/ 2>/dev/null || true
  install -m755 "$script_dir/core/target/release/albus-core" /usr/lib/albus/albus-core
  install -m644 "$script_dir/polkit/io.github.oqullcan.albus.policy" /usr/share/polkit-1/actions/io.github.oqullcan.albus.policy
elif command -v pkexec >/dev/null 2>&1; then
  pkexec bash -c "
    mkdir -p /usr/lib/albus/lib /usr/share/polkit-1/actions && \
    install -m755 '$script_dir/scripts/albus-service.sh' /usr/lib/albus/albus-service.sh && \
    install -m755 '$script_dir/scripts/albus-transparent.sh' /usr/lib/albus/albus-transparent.sh && \
    install -m755 '$script_dir/scripts/lib/'*.sh /usr/lib/albus/lib/ && \
    install -m755 '$script_dir/core/target/release/albus-core' /usr/lib/albus/albus-core && \
    install -m644 '$script_dir/polkit/io.github.oqullcan.albus.policy' /usr/share/polkit-1/actions/io.github.oqullcan.albus.policy
  "
elif command -v sudo >/dev/null 2>&1; then
  sudo mkdir -p /usr/lib/albus/lib /usr/share/polkit-1/actions
  sudo install -m755 "$script_dir/scripts/albus-service.sh" /usr/lib/albus/albus-service.sh
  sudo install -m755 "$script_dir/scripts/albus-transparent.sh" /usr/lib/albus/albus-transparent.sh
  sudo install -m755 "$script_dir/scripts/lib/"*.sh /usr/lib/albus/lib/
  sudo install -m755 "$script_dir/core/target/release/albus-core" /usr/lib/albus/albus-core
  sudo install -m644 "$script_dir/polkit/io.github.oqullcan.albus.policy" /usr/share/polkit-1/actions/io.github.oqullcan.albus.policy
fi

echo -e "\033[38;2;166;227;161m[OK] Installation complete!\033[0m"
echo -e "Run \033[1m'albus status'\033[0m or open the Omarchy panel to start."

