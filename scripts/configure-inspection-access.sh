#!/usr/bin/env bash
# Grant the dedicated M3 sensor search-only access through privileged parents.
set -Eeuo pipefail

root=''
if [[ ${1:-} == --root && $# == 2 ]]; then
  root=$(readlink -f -- "$2")
elif (($#)); then
  echo 'usage: configure-inspection-access.sh [--root staged-filesystem]' >&2
  exit 2
fi
[[ $EUID -eq 0 ]] || { echo 'run as root' >&2; exit 1; }
for command in setfacl runuser id; do
  command -v "$command" >/dev/null || { echo "missing command: $command" >&2; exit 1; }
done
id ngfw-inspect >/dev/null
[[ $(id -u ngfw-inspect) != 0 ]] || { echo 'sensor account must not be root' >&2; exit 1; }

for parent in "$root/etc/ngfw" "$root/var/lib/ngfw"; do
  [[ -d $parent && ! -L $parent ]] || { echo "invalid appliance directory: $parent" >&2; exit 1; }
done
# No management group membership, world access, recursive ACLs or default ACLs.
# Preserve other named entries (including the M4 proxy's traversal grant).
setfacl -m u:ngfw-inspect:--x "$root/etc/ngfw" "$root/var/lib/ngfw"

sensor_test() { runuser -u ngfw-inspect -- test "$@"; }
for parent in "$root/etc/ngfw" "$root/var/lib/ngfw"; do
  if ! sensor_test -x "$parent" || sensor_test -r "$parent" || sensor_test -w "$parent"; then
    echo "sensor needs search-only access to $parent" >&2
    exit 1
  fi
done
for mode in ids ips; do
  config="$root/etc/ngfw/inspection/$mode.yaml"
  runtime="$root/var/lib/ngfw/inspection/$mode"
  if ! sensor_test -r "$config" || sensor_test -w "$config"; then
    echo "sensor needs read-only access to $config" >&2
    exit 1
  fi
  if ! sensor_test -x "$runtime" || ! sensor_test -w "$runtime"; then
    echo "sensor cannot write runtime directory $runtime" >&2
    exit 1
  fi
done
for relative in etc/ngfw/ngfw.env etc/ngfw/proxy.env var/lib/ngfw/running.json var/lib/ngfw/dataplane-applied.json; do
  path="$root/$relative"
  if [[ -e $path ]] && { sensor_test -r "$path" || sensor_test -w "$path"; }; then
    echo "sensor can access privileged file $path; correct its ownership/mode" >&2
    exit 1
  fi
done
for relative in var/lib/ngfw/management var/lib/ngfw/ca var/lib/ngfw/request-workers; do
  path="$root/$relative"
  if [[ -d $path ]] && sensor_test -x "$path"; then
    echo "sensor can enter private directory $path; correct its ownership/mode" >&2
    exit 1
  fi
done
echo 'M3 sensor access verified: config read-only, runtime writable, privileged state inaccessible'
