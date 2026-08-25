#!/bin/bash
# albus transparent interception with stealth loopback, tcp mss clamping & zero plaintext dns fallback

set -u



action="${1:-enable}"
custom_bootstraps="${2:-}"
port="1080"

teardown_all() {
  # 1. remove jump rules from main tables in loops
  while iptables -D OUTPUT -j ALBUS_OUT 2>/dev/null; do :; done
  while iptables -D INPUT -j ALBUS_IN 2>/dev/null; do :; done
  while ip6tables -D OUTPUT -j ALBUS_OUT6 2>/dev/null; do :; done

  while iptables -D OUTPUT -j ALBUS_FILTER 2>/dev/null; do :; done
  while iptables -D INPUT -j ALBUS_FILTER 2>/dev/null; do :; done
  while ip6tables -D OUTPUT -j ALBUS_FILTER6 2>/dev/null; do :; done
  while ip6tables -D INPUT -j ALBUS_FILTER6 2>/dev/null; do :; done

  while iptables -t nat -D OUTPUT -j ALBUS 2>/dev/null; do :; done
  while iptables -t nat -D OUTPUT -p tcp -j ALBUS 2>/dev/null; do :; done
  while iptables -t nat -D OUTPUT -j ALBUS_DNS 2>/dev/null; do :; done
  while iptables -t nat -D OUTPUT -p udp --dport 53 -j ALBUS_DNS 2>/dev/null; do :; done
  while iptables -t nat -D OUTPUT -p tcp --dport 53 -j ALBUS_DNS 2>/dev/null; do :; done
  while iptables -t nat -D PREROUTING -j ALBUS_DNS 2>/dev/null; do :; done
  while iptables -t nat -D PREROUTING -j ALBUS 2>/dev/null; do :; done

  while ip6tables -t nat -D OUTPUT -j ALBUS 2>/dev/null; do :; done
  while ip6tables -t nat -D OUTPUT -p tcp -j ALBUS 2>/dev/null; do :; done
  while ip6tables -t nat -F ALBUS 2>/dev/null; do :; done
  while ip6tables -t nat -X ALBUS 2>/dev/null; do :; done

  while iptables -t mangle -D OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360 2>/dev/null; do :; done

  # 2. flush and delete custom chains
  iptables -F ALBUS_OUT 2>/dev/null || true
  iptables -X ALBUS_OUT 2>/dev/null || true
  iptables -F ALBUS_IN 2>/dev/null || true
  iptables -X ALBUS_IN 2>/dev/null || true
  ip6tables -F ALBUS_OUT6 2>/dev/null || true
  ip6tables -X ALBUS_OUT6 2>/dev/null || true

  iptables -F ALBUS_FILTER 2>/dev/null || true
  iptables -X ALBUS_FILTER 2>/dev/null || true
  ip6tables -F ALBUS_FILTER6 2>/dev/null || true
  ip6tables -X ALBUS_FILTER6 2>/dev/null || true

  iptables -t nat -F ALBUS 2>/dev/null || true
  iptables -t nat -X ALBUS 2>/dev/null || true
  iptables -t nat -F ALBUS_DNS 2>/dev/null || true
  iptables -t nat -X ALBUS_DNS 2>/dev/null || true

  while iptables -D OUTPUT -p udp --dport 53 -j DROP 2>/dev/null; do :; done
  while iptables -D OUTPUT -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null; do :; done

  while ip6tables -D OUTPUT -p tcp -m multiport --dports 80,443 -j REJECT --reject-with tcp-reset 2>/dev/null; do :; done
  while ip6tables -D OUTPUT -p udp --dport 443 -j REJECT 2>/dev/null; do :; done
  while ip6tables -D OUTPUT -p udp --dport 53 -j REJECT 2>/dev/null; do :; done
  while ip6tables -D INPUT ! -i lo -p tcp --dport "$port" -j DROP 2>/dev/null; do :; done
  while ip6tables -D INPUT ! -i lo -p udp --dport 5300 -j DROP 2>/dev/null; do :; done
  while ip6tables -D INPUT ! -i lo -p tcp --dport 5300 -j DROP 2>/dev/null; do :; done
}



if [ "$action" = "enable" ]; then
  teardown_all

  # 1. create atomic filter chains
  iptables -N ALBUS_OUT
  iptables -A ALBUS_OUT -m mark --mark 0x1337 -j RETURN
  iptables -A ALBUS_OUT -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable

  iptables -N ALBUS_IN
  iptables -A ALBUS_IN ! -i lo -p tcp --dport "$port" -j DROP
  iptables -A ALBUS_IN ! -i lo -p udp --dport 5300 -j DROP
  iptables -A ALBUS_IN ! -i lo -p tcp --dport 5300 -j DROP

  ip6tables -N ALBUS_OUT6
  ip6tables -A ALBUS_OUT6 -p tcp -m multiport --dports 80,443 -j REJECT --reject-with tcp-reset
  ip6tables -A ALBUS_OUT6 -p udp --dport 443 -j REJECT
  ip6tables -A ALBUS_OUT6 -p udp --dport 53 -j REJECT

  # 2. create nat tcp chain
  iptables -t nat -N ALBUS
  iptables -t nat -A ALBUS -m mark --mark 0x1337 -j RETURN
  iptables -t nat -A ALBUS -d 0.0.0.0/8 -j RETURN
  iptables -t nat -A ALBUS -d 10.0.0.0/8 -j RETURN
  iptables -t nat -A ALBUS -d 127.0.0.0/8 -j RETURN
  iptables -t nat -A ALBUS -d 169.254.0.0/16 -j RETURN
  iptables -t nat -A ALBUS -d 172.16.0.0/12 -j RETURN
  iptables -t nat -A ALBUS -d 192.168.0.0/16 -j RETURN

  # bypass upstream doh resolvers
  iptables -t nat -A ALBUS -d 9.9.9.9 -j RETURN
  iptables -t nat -A ALBUS -d 149.112.112.112 -j RETURN
  iptables -t nat -A ALBUS -d 1.1.1.1 -j RETURN
  iptables -t nat -A ALBUS -d 1.0.0.1 -j RETURN
  iptables -t nat -A ALBUS -d 94.140.14.14 -j RETURN
  iptables -t nat -A ALBUS -d 94.140.15.15 -j RETURN
  iptables -t nat -A ALBUS -d 45.90.28.0/24 -j RETURN
  iptables -t nat -A ALBUS -d 45.90.30.0/24 -j RETURN

  if [ -n "$custom_bootstraps" ]; then
    IFS=',' read -ra ADDR <<< "$custom_bootstraps"
    for ip in "${ADDR[@]}"; do
      trimmed=$(echo "$ip" | xargs)
      if [[ $trimmed =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        iptables -t nat -A ALBUS -d "$trimmed" -j RETURN
      fi
    done
  fi

  iptables -t nat -A ALBUS -p tcp --dport 80 -j REDIRECT --to-ports "$port"
  iptables -t nat -A ALBUS -p tcp --dport 443 -j REDIRECT --to-ports "$port"

  # 3. create nat dns chain
  iptables -t nat -N ALBUS_DNS
  iptables -t nat -A ALBUS_DNS -m mark --mark 0x1337 -j RETURN
  iptables -t nat -A ALBUS_DNS -d 127.0.0.0/8 -j RETURN
  iptables -t nat -A ALBUS_DNS -d 10.0.0.0/8 -j RETURN
  iptables -t nat -A ALBUS_DNS -d 172.16.0.0/12 -j RETURN
  iptables -t nat -A ALBUS_DNS -d 192.168.0.0/16 -j RETURN
  iptables -t nat -A ALBUS_DNS -p udp --dport 53 -j REDIRECT --to-ports 5300
  iptables -t nat -A ALBUS_DNS -p tcp --dport 53 -j REDIRECT --to-ports 5300

  # 4. link into system packet flow
  iptables -I OUTPUT 1 -j ALBUS_OUT
  iptables -I INPUT 1 -j ALBUS_IN
  ip6tables -I OUTPUT 1 -j ALBUS_OUT6

  iptables -t nat -I OUTPUT 1 -p tcp -j ALBUS
  iptables -t nat -I OUTPUT 1 -p udp --dport 53 -j ALBUS_DNS
  iptables -t nat -I OUTPUT 1 -p tcp --dport 53 -j ALBUS_DNS
  iptables -t mangle -I OUTPUT 1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360 2>/dev/null || true

  echo "{\"transparent\":\"enabled\"}"
else
  teardown_all
  echo "{\"transparent\":\"disabled\"}"
fi


