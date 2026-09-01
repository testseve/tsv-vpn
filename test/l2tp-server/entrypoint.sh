#!/bin/sh
set -eu

# The "remote network" is a dummy interface holding a few addresses for scans
# and health checks to hit.
ip link add lab type dummy
ip addr add 198.51.100.1/24 dev lab
ip addr add 198.51.100.10/32 dev lab
ip addr add 198.51.100.20/32 dev lab
ip addr add 203.0.113.1/24 dev lab
ip addr add 203.0.113.10/32 dev lab
ip link set lab up

sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

# Drop bare L2TP like a real endpoint would; otherwise a client with the
# wrong PSK still connects and the drills prove nothing.
iptables -A INPUT -p udp --dport 1701 -m policy --dir in --pol ipsec -j ACCEPT
iptables -A INPUT -p udp --dport 1701 -j DROP

mkdir -p /var/run/xl2tpd

/usr/lib/ipsec/charon &
sleep 2
swanctl --load-all --noprompt

exec xl2tpd -D
