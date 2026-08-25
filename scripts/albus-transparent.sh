#!/bin/bash
# albus transparent interception with stealth loopback, tcp mss clamping & zero plaintext dns fallback

set -euo pipefail

action="${1:-enable}"
custom_bootstraps="${2:-}"
port="1080"

if [ "$action" = "enable" ]; then
  # 1. clean previous ipv4 rules
  iptables -t nat -D OUTPUT -p tcp -j ALBUS 2>/dev/null || true
  iptables -t nat -D OUTPUT -p udp --dport 53 -j ALBUS_DNS 2>/dev/null || true
  iptables -t nat -D OUTPUT -p tcp --dport 53 -j ALBUS_DNS 2>/dev/null || true
  iptables -t nat -F ALBUS 2>/dev/null || true
  iptables -t nat -X ALBUS 2>/dev/null || true
  iptables -t nat -F ALBUS_DNS 2>/dev/null || true
  iptables -t nat -X ALBUS_DNS 2>/dev/null || true
  iptables -t mangle -D OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360 2>/dev/null || true
  iptables -D OUTPUT -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || true
  iptables -D OUTPUT -p udp --dport 53 ! -d 127.0.0.1 ! -d 10.0.0.0/8 ! -d 172.16.0.0/12 ! -d 192.168.0.0/16 -j DROP 2>/dev/null || true
  iptables -D OUTPUT -p udp --dport 53 ! -d 127.0.0.1 -j DROP 2>/dev/null || true
  iptables -D INPUT ! -i lo -p tcp --dport "$port" -j DROP 2>/dev/null || true
  iptables -D INPUT ! -i lo -p udp --dport 5300 -j DROP 2>/dev/null || true
  iptables -D INPUT ! -i lo -p tcp --dport 5300 -j DROP 2>/dev/null || true

  # 2. clean previous ipv6 rules
  ip6tables -D OUTPUT -p tcp -m multiport --dports 80,443 -j REJECT --reject-with tcp-reset 2>/dev/null || true
  ip6tables -D OUTPUT -p udp --dport 443 -j REJECT 2>/dev/null || true
  ip6tables -D OUTPUT -p udp --dport 53 -j REJECT 2>/dev/null || true
  ip6tables -D INPUT ! -i lo -p tcp --dport "$port" -j DROP 2>/dev/null || true
  ip6tables -D INPUT ! -i lo -p udp --dport 5300 -j DROP 2>/dev/null || true
  ip6tables -D INPUT ! -i lo -p tcp --dport 5300 -j DROP 2>/dev/null || true

  # 3. stealth port scan protection (drop all non-loopback probe packets on local proxy & dns ports)
  iptables -I INPUT 1 ! -i lo -p tcp --dport "$port" -j DROP
  iptables -I INPUT 1 ! -i lo -p udp --dport 5300 -j DROP
  iptables -I INPUT 1 ! -i lo -p tcp --dport 5300 -j DROP
  ip6tables -I INPUT 1 ! -i lo -p tcp --dport "$port" -j DROP
  ip6tables -I INPUT 1 ! -i lo -p udp --dport 5300 -j DROP
  ip6tables -I INPUT 1 ! -i lo -p tcp --dport 5300 -j DROP

  # 4. tcp mss clamping (forces micro-segmentation to defeat mtu chunk analysis)
  iptables -t mangle -I OUTPUT 1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360 2>/dev/null || true

  # 5. create ipv4 tcp chain
  iptables -t nat -N ALBUS
  iptables -t nat -A ALBUS -m mark --mark 0x1337 -j RETURN

  # bypass local network and loopback
  iptables -t nat -A ALBUS -d 0.0.0.0/8 -j RETURN
  iptables -t nat -A ALBUS -d 10.0.0.0/8 -j RETURN
  iptables -t nat -A ALBUS -d 127.0.0.0/8 -j RETURN
  iptables -t nat -A ALBUS -d 169.254.0.0/16 -j RETURN
  iptables -t nat -A ALBUS -d 172.16.0.0/12 -j RETURN
  iptables -t nat -A ALBUS -d 192.168.0.0/16 -j RETURN

  # bypass specific user UID or cgroup v2 path if configured
  if [ -n "${ALBUS_BYPASS_UID:-}" ]; then
    iptables -t nat -A ALBUS -m owner --uid-owner "$ALBUS_BYPASS_UID" -j RETURN 2>/dev/null || true
  fi
  if [ -n "${ALBUS_BYPASS_CGROUP:-}" ]; then
    iptables -t nat -A ALBUS -m cgroup --path "$ALBUS_BYPASS_CGROUP" -j RETURN 2>/dev/null || true
  fi



  # bypass upstream doh resolvers
  iptables -t nat -A ALBUS -d 9.9.9.9 -j RETURN
  iptables -t nat -A ALBUS -d 149.112.112.112 -j RETURN
  iptables -t nat -A ALBUS -d 1.1.1.1 -j RETURN
  iptables -t nat -A ALBUS -d 1.0.0.1 -j RETURN
  iptables -t nat -A ALBUS -d 94.140.14.14 -j RETURN
  iptables -t nat -A ALBUS -d 94.140.15.15 -j RETURN
  iptables -t nat -A ALBUS -d 45.90.28.0/24 -j RETURN
  iptables -t nat -A ALBUS -d 45.90.30.0/24 -j RETURN

  # dynamically bypass custom doh bootstrap ips
  if [ -n "$custom_bootstraps" ]; then
    IFS=',' read -ra ADDR <<< "$custom_bootstraps"
    for ip in "${ADDR[@]}"; do
      trimmed=$(echo "$ip" | xargs)
      if [[ $trimmed =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        iptables -t nat -A ALBUS -d "$trimmed" -j RETURN
      fi
    done
  fi

  # redirect http and https to albus core
  iptables -t nat -A ALBUS -p tcp --dport 80 -j REDIRECT --to-ports "$port"
  iptables -t nat -A ALBUS -p tcp --dport 443 -j REDIRECT --to-ports "$port"
  iptables -t nat -A OUTPUT -p tcp -j ALBUS

  # 6. create ipv4 dns chain with local lan / pi-hole bypass support
  iptables -t nat -N ALBUS_DNS
  iptables -t nat -A ALBUS_DNS -m mark --mark 0x1337 -j RETURN
  iptables -t nat -A ALBUS_DNS -d 127.0.0.0/8 -j RETURN
  iptables -t nat -A ALBUS_DNS -d 10.0.0.0/8 -j RETURN
  iptables -t nat -A ALBUS_DNS -d 172.16.0.0/12 -j RETURN
  iptables -t nat -A ALBUS_DNS -d 192.168.0.0/16 -j RETURN
  iptables -t nat -A ALBUS_DNS -p udp --dport 53 -j REDIRECT --to-ports 5300
  iptables -t nat -A ALBUS_DNS -p tcp --dport 53 -j REDIRECT --to-ports 5300
  iptables -t nat -A OUTPUT -p udp --dport 53 -j ALBUS_DNS
  iptables -t nat -A OUTPUT -p tcp --dport 53 -j ALBUS_DNS

  # 7. quic blocker: forces browsers to use tcp tls 1.3
  iptables -I OUTPUT 1 -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || true

  # 8. dead-man switch: drop all unencrypted outgoing external plaintext dns packets (preserves local lan)
  iptables -I OUTPUT 1 -p udp --dport 53 ! -d 127.0.0.1 ! -d 10.0.0.0/8 ! -d 172.16.0.0/12 ! -d 192.168.0.0/16 -j DROP 2>/dev/null || true

  # 9. strict ipv6 leak protection
  ip6tables -I OUTPUT 1 -p tcp -m multiport --dports 80,443 -j REJECT --reject-with tcp-reset 2>/dev/null || true
  ip6tables -I OUTPUT 1 -p udp --dport 443 -j REJECT 2>/dev/null || true
  ip6tables -I OUTPUT 1 -p udp --dport 53 -j REJECT 2>/dev/null || true

  echo "{\"transparent\":\"enabled\"}"
else
  # clean up all ipv4 and ipv6 rules
  iptables -t nat -D OUTPUT -p tcp -j ALBUS 2>/dev/null || true
  iptables -t nat -D OUTPUT -p udp --dport 53 -j ALBUS_DNS 2>/dev/null || true
  iptables -t nat -D OUTPUT -p tcp --dport 53 -j ALBUS_DNS 2>/dev/null || true
  iptables -t nat -F ALBUS 2>/dev/null || true
  iptables -t nat -X ALBUS 2>/dev/null || true
  iptables -t nat -F ALBUS_DNS 2>/dev/null || true
  iptables -t nat -X ALBUS_DNS 2>/dev/null || true
  iptables -t mangle -D OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360 2>/dev/null || true
  iptables -D OUTPUT -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || true
  iptables -D OUTPUT -p udp --dport 53 ! -d 127.0.0.1 ! -d 10.0.0.0/8 ! -d 172.16.0.0/12 ! -d 192.168.0.0/16 -j DROP 2>/dev/null || true
  iptables -D OUTPUT -p udp --dport 53 ! -d 127.0.0.1 -j DROP 2>/dev/null || true
  iptables -D INPUT ! -i lo -p tcp --dport "$port" -j DROP 2>/dev/null || true
  iptables -D INPUT ! -i lo -p udp --dport 5300 -j DROP 2>/dev/null || true
  iptables -D INPUT ! -i lo -p tcp --dport 5300 -j DROP 2>/dev/null || true

  ip6tables -D OUTPUT -p tcp -m multiport --dports 80,443 -j REJECT --reject-with tcp-reset 2>/dev/null || true
  ip6tables -D OUTPUT -p udp --dport 443 -j REJECT 2>/dev/null || true
  ip6tables -D OUTPUT -p udp --dport 53 -j REJECT 2>/dev/null || true
  ip6tables -D INPUT ! -i lo -p tcp --dport "$port" -j DROP 2>/dev/null || true
  ip6tables -D INPUT ! -i lo -p udp --dport 5300 -j DROP 2>/dev/null || true
  ip6tables -D INPUT ! -i lo -p tcp --dport 5300 -j DROP 2>/dev/null || true

  echo "{\"transparent\":\"disabled\"}"
fi
