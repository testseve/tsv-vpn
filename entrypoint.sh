#!/bin/sh
set -eu

# Password subcommands skip the device checks; they run before the container
# is configured or after a lockout.
case "${1:-}" in
    hash-password | reset-password)
        exec /usr/local/bin/tsv-vpn "$@"
        ;;
esac

# Docker mounts /proc/sys read-only; best effort, the real setting comes from
# the compose sysctls key. Without forwarding the node routes nothing.
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true

if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then
    echo "net.ipv4.ip_forward is 0; set it via the sysctls key in compose" >&2
    exit 1
fi

# v6 forwarding is only a warning; v4-only sites don't care.
if [ "$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo 1)" != "1" ]; then
    echo "warning: net.ipv6.conf.all.forwarding is 0; IPv6 subnets will not route" >&2
fi

if [ ! -c /dev/net/tun ]; then
    echo "/dev/net/tun missing; add devices: [/dev/net/tun] and cap_add: [NET_ADMIN]" >&2
    exit 1
fi

if [ ! -c /dev/ppp ]; then
    echo "/dev/ppp missing; add devices: [/dev/ppp] and load ppp_generic on the host" >&2
    exit 1
fi

mkdir -p "${TS_STATE_DIR:-/var/lib/tailscale}" /var/run/tailscale

exec /usr/local/bin/tsv-vpn "$@"
