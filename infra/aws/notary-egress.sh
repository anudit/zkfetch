#!/usr/bin/env bash
# Run on the Docker host after creating network zkf. Restricts forwarded
# notary egress independently of DNS/application classification.
set -euo pipefail
bridge="br-$(docker network inspect zkf --format '{{.Id}}' | cut -c1-12)"
iptables -N ZKF-EGRESS 2>/dev/null || true
iptables -F ZKF-EGRESS
iptables -A ZKF-EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
for cidr in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 192.0.0.0/24 192.0.2.0/24 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4; do
  iptables -A ZKF-EGRESS -d "$cidr" -j REJECT
done
iptables -A ZKF-EGRESS -p tcp --dport 443 -j RETURN
iptables -A ZKF-EGRESS -j REJECT
iptables -C DOCKER-USER -i "$bridge" ! -o "$bridge" -j ZKF-EGRESS 2>/dev/null ||
  iptables -I DOCKER-USER 1 -i "$bridge" ! -o "$bridge" -j ZKF-EGRESS
# This Docker bridge uses IPv4 only; fail deployment if IPv6 was enabled.
test "$(docker network inspect zkf --format '{{.EnableIPv6}}')" = false
# Container-to-host traffic uses INPUT rather than DOCKER-USER. No new
# connections from this dedicated bridge to host services are required.
iptables -C INPUT -i "$bridge" -m conntrack --ctstate NEW -j REJECT 2>/dev/null ||
  iptables -I INPUT 1 -i "$bridge" -m conntrack --ctstate NEW -j REJECT
