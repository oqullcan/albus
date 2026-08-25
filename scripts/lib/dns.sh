#!/bin/bash
# albus DNS & systemd-resolved management module

set -u

# Apply Albus DoH listener (127.0.0.1:5300) to physical interfaces
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

# Restore native network DNS settings cleanly on physical interfaces
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

  # Flush both resolved and kernel route caches
  resolvectl flush-caches 2>/dev/null || true
  ip route flush cache 2>/dev/null || true
}
