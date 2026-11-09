#!/usr/bin/env bash
# Install the optional exemption without rebuilding or restarting NGFW backends.
set -Eeuo pipefail
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
enable=0
if [[ ${1:-} == --enable && $# -eq 1 ]]; then enable=1
elif [[ $# -ne 0 ]]; then die 'Usage: sudo bash scripts/install-api-loopback-notrack.sh [--enable]'; fi
[[ $EUID -eq 0 ]] || die 'Run as root.'
for tool in nft jq conntrack flock install systemctl; do command -v "$tool" >/dev/null || die "Missing command: $tool"; done
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
install -d -o root -g root -m 0755 /usr/local/lib/ngfw
# Preserve existing /etc/ngfw directory ownership/access used by engine/proxy.
[[ -d /etc/ngfw ]] || install -d -o root -g root -m 0755 /etc/ngfw
install -o root -g root -m 0755 "$repo/scripts/api-loopback-notrack.sh" /usr/local/lib/ngfw/api-loopback-notrack.sh
install -o root -g root -m 0644 "$repo/deploy/api-loopback-notrack.nft" /etc/ngfw/api-loopback-notrack.nft
install -o root -g root -m 0644 "$repo/deploy/ngfw-api-loopback-notrack.service" /etc/systemd/system/ngfw-api-loopback-notrack.service
systemctl daemon-reload
if [[ $enable -eq 1 ]]; then
  # Start before enabling: a failed drain check must not enable a broken boot unit.
  systemctl start ngfw-api-loopback-notrack.service
  systemctl enable ngfw-api-loopback-notrack.service
else
  printf 'Installed. After draining tracked local API sockets, run:\n  sudo systemctl enable --now ngfw-api-loopback-notrack.service\n'
fi
