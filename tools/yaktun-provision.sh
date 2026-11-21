#!/bin/sh
# yaktun-provision.sh — create the persistent yak0 TUN for an unprivileged
# yakmesh node. Run once as root (manual), at boot (yakmesh-tun.service),
# or via a scoped sudoers rule so the node can self-provision.
#
#   yaktun-provision.sh <owner-user> <vip4> <vip6> [iface]
#
# Example:  sudo tools/yaktun-provision.sh alice 10.199.7.42 \
#               fd99:199:8ed6:ead1::1 yak0
#
# What it does (and ONLY this — keep it narrow, it runs as root):
#   1. ip tuntap add dev <iface> mode tun user <owner>   (idempotent)
#   2. replace <vip4>/16 + <vip6>/64 on <iface>, link up
#   3. ip route replace 10.199.0.0/16 dev <iface>  (mesh subnet on-link;
#      peer VIPs need no per-peer host routes under the /16 layout)
#      + fd99:199::/48 symmetric guard for the derived v6 VIP space
#   4. writes /etc/yakmesh/tun.env so yakmesh-tun.service can replay
#      this exact provisioning at boot.
#
# Scoped self-provisioning (optional): /etc/sudoers.d/yakmesh-tun
#   %yakmesh ALL=(root) NOPASSWD: /usr/lib/yakmesh/tools/yaktun-provision.sh
# The node calls this script via `sudo -n` when the device is absent.

set -eu

OWNER="${1:?usage: yaktun-provision.sh <owner-user> <vip4> <vip6> [iface]}"
VIP4="${2:?missing virtual IPv4 (10.199.x.y)}"
VIP6="${3:?missing virtual IPv6}"
IFACE="${4:-yak0}"

case "$VIP4" in
    10.199.*.*) ;;
    *) echo "yaktun-provision: refusing non-mesh vip4 '$VIP4'" >&2; exit 2 ;;
esac
case "$IFACE" in
    yak*) ;;
    *) echo "yaktun-provision: refusing iface '$IFACE' (must match yak*)" >&2; exit 2 ;;
esac

ip -d tuntap show 2>/dev/null | grep -q "^${IFACE}:" \
    || ip tuntap add dev "$IFACE" mode tun user "$OWNER"

ip addr flush dev "$IFACE" 2>/dev/null || true
ip -6 addr flush dev "$IFACE" 2>/dev/null || true
if [ "${YAKTUN_REPLAY:-0}" = "1" ]; then
    # Boot replay: stored VIPs go stale when nodeId re-derives per boot —
    # the node rebinds its derived VIP on attach regardless. Skip the
    # bind so 'ip addr' never shows an address the node won't claim.
    echo "yaktun-provision: replay mode — iface only; node re-derives VIP on attach"
else
    ip addr replace "$VIP4/16" dev "$IFACE"
    ip -6 addr replace "$VIP6/64" dev "$IFACE"
fi
ip link set dev "$IFACE" up
ip route replace 10.199.0.0/16 dev "$IFACE"
ip -6 route replace fd99:199::/48 dev "$IFACE"

mkdir -p /etc/yakmesh
printf 'YAKTUN_USER=%s\nYAKTUN_VIP4=%s\nYAKTUN_VIP6=%s\nYAKTUN_IFACE=%s\n' \
    "$OWNER" "$VIP4" "$VIP6" "$IFACE" > /etc/yakmesh/tun.env
chmod 600 /etc/yakmesh/tun.env

echo "yaktun-provision: $IFACE up — $VIP4/16, $VIP6/64 (owner $OWNER, replayed at boot via tun.env)"
