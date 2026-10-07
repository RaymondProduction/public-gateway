#!/bin/sh
# Runs INSIDE the WireGuard network namespace, never on the VPS host.
set -eu
mode=${1:?up or down}
iface=${2:?interface}
[ "$iface" = wg0 ] || { echo "Unexpected interface" >&2; exit 1; }
case "$mode" in
  up)
    iptables -w -N PGW_INPUT 2>/dev/null || true
    iptables -w -F PGW_INPUT
    iptables -w -A PGW_INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -w -A PGW_INPUT -p icmp --icmp-type echo-request -j ACCEPT
    iptables -w -A PGW_INPUT -j DROP
    iptables -w -C INPUT -i "$iface" -j PGW_INPUT 2>/dev/null || \
      iptables -w -I INPUT 1 -i "$iface" -j PGW_INPUT
    iptables -w -C FORWARD -i "$iface" -j DROP 2>/dev/null || \
      iptables -w -I FORWARD 1 -i "$iface" -j DROP
    ;;
  down)
    while iptables -w -C INPUT -i "$iface" -j PGW_INPUT 2>/dev/null; do
      iptables -w -D INPUT -i "$iface" -j PGW_INPUT
    done
    while iptables -w -C FORWARD -i "$iface" -j DROP 2>/dev/null; do
      iptables -w -D FORWARD -i "$iface" -j DROP
    done
    iptables -w -F PGW_INPUT 2>/dev/null || true
    iptables -w -X PGW_INPUT 2>/dev/null || true
    ;;
  *) echo "Usage: $0 up|down wg0" >&2; exit 2 ;;
esac
