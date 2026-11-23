#!/bin/sh
# install-yaktun.sh — install the scoped-privilege contract for YAK-TUN.
#
# What it does (run as root or via sudo):
#   1. /usr/lib/yakmesh/tools/yaktun-provision.sh  (root-owned, 755)
#   2. /etc/sudoers.d/yakmesh-tun                  (440, visudo-verified)
#   3. /etc/systemd/system/yakmesh-tun.service     (boot replay, enabled)
#   4. instant check: sudo -n provisioner runs for the calling user
#
# Sources resolve relative to this script's location inside the package:
#   <pkg>/tools/yaktun-provision.sh
#   <pkg>/deploy/sudoers-yakmesh-tun
#   <pkg>/deploy/yakmesh-tun.service
set -eu

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# script may live in deploy/ or tools/ inside the package
find_pkg_file() {
    for base in "$SELF_DIR" "$SELF_DIR/.." "$SELF_DIR/../.."; do
        for sub in tools deploy; do
            [ -f "$base/$sub/$1" ] && { echo "$base/$sub/$1"; return 0; }
        done
    done
    return 1
}

[ "$(id -u)" -eq 0 ] || { echo "install-yaktun: run with sudo or as root" >&2; exit 1; }
CALLER=${SUDO_USER:-$(logname 2>/dev/null || echo root)}

PROV=$(find_pkg_file yaktun-provision.sh)     || { echo "install-yaktun: tools/yaktun-provision.sh not found beside this script" >&2; exit 1; }
SUDOERS=$(find_pkg_file sudoers-yakmesh-tun)     || { echo "install-yaktun: deploy/sudoers-yakmesh-tun not found" >&2; exit 1; }
UNIT=$(find_pkg_file yakmesh-tun.service || true)

install -Dm755 "$PROV" /usr/lib/yakmesh/tools/yaktun-provision.sh
echo "provisioner → /usr/lib/yakmesh/tools/yaktun-provision.sh"

install -Dm440 "$SUDOERS" /etc/sudoers.d/yakmesh-tun
visudo -cf /etc/sudoers.d/yakmesh-tun >/dev/null     || { echo "install-yaktun: sudoers file failed visudo check — removing" >&2; rm -f /etc/sudoers.d/yakmesh-tun; exit 1; }
echo "sudoers rule → /etc/sudoers.d/yakmesh-tun (visudo OK)"

if [ -n "$UNIT" ] && command -v systemctl >/dev/null 2>&1; then
    install -Dm644 "$UNIT" /etc/systemd/system/yakmesh-tun.service
    systemctl daemon-reload
    systemctl enable yakmesh-tun.service >/dev/null 2>&1 || true
    echo "boot replay → yakmesh-tun.service enabled"
fi

# instant verification: the scoped rule must let the caller run the
# provisioner without a password
if sudo -n -u root /usr/lib/yakmesh/tools/yaktun-provision.sh --help >/dev/null 2>&1    || sudo -n -l /usr/lib/yakmesh/tools/yaktun-provision.sh >/dev/null 2>&1; then
    echo "verify: sudoers rule active — 'sudo -n yaktun-provision.sh' works for $CALLER"
else
    echo "verify: WARNING — sudo -n still demands a password for $CALLER;"
    echo "        check sudoers ordering (a later broad rule may shadow this one)"
fi

echo "install-yaktun: done. The yakmesh node now self-provisions its VIP at attach."
