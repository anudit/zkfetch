#!/usr/bin/env bash
# Native service egress: dedicated UID, exact DNS resolvers, public IPv4 HTTPS.
# Run before starting the notary; systemd restores the policy on every boot.
set -euo pipefail
uid=$(id -u zkf-notary)
[[ "$uid" -ne 0 ]] || { echo 'notary must have a non-root UID' >&2; exit 1; }
iptables -N ZKF-EGRESS 2>/dev/null || true
iptables -F ZKF-EGRESS
iptables -A ZKF-EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
# Replies to Caddy are established traffic. New loopback connections are denied
# except DNS to the configured resolver, which may be a local stub.
conf=/etc/resolv.conf
resolvers=$(awk '$1 == "nameserver" && $2 ~ /^[0-9.]+$/ { print $2 }' "$conf")
[[ -n "$resolvers" ]] || { echo 'no IPv4 DNS resolver configured' >&2; exit 1; }
for ns in $resolvers; do
  iptables -A ZKF-EGRESS -d "$ns" -p udp --dport 53 -j RETURN
  iptables -A ZKF-EGRESS -d "$ns" -p tcp --dport 53 -j RETURN
done
for cidr in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 192.0.0.0/24 192.0.2.0/24 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4; do
  iptables -A ZKF-EGRESS -d "$cidr" -j REJECT
done
iptables -A ZKF-EGRESS -p tcp --dport 443 -j RETURN
iptables -A ZKF-EGRESS -j REJECT
iptables -C OUTPUT -m owner --uid-owner "$uid" -j ZKF-EGRESS 2>/dev/null ||
  iptables -I OUTPUT 1 -m owner --uid-owner "$uid" -j ZKF-EGRESS
# Keep the previous deployment's IPv4-only notary egress. Other host users,
# including Caddy and SSH, retain their own networking.
ip6tables -C OUTPUT -m owner --uid-owner "$uid" -j REJECT 2>/dev/null ||
  ip6tables -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
