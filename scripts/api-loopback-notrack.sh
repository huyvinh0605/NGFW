#!/usr/bin/env bash
# Manage only our optional table. Never flush conntrack or other nft tables.
set -Eeuo pipefail

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
action=${1:-}
[[ $# -eq 1 && ( "$action" == apply || "$action" == remove || "$action" == status ) ]] || die 'Usage: api-loopback-notrack.sh apply|remove|status'
[[ $EUID -eq 0 ]] || die 'Run as root.'
for tool in nft jq flock mktemp; do command -v "$tool" >/dev/null || die "Missing command: $tool"; done
rules=${NGFW_API_LOOPBACK_RULES:-/etc/ngfw/api-loopback-notrack.nft}
runtime=${NGFW_API_LOOPBACK_RUNTIME:-/run/ngfw-api-loopback-notrack}
table=ngfw_api_loopback_notrack
owner='owner=ngfw-api-loopback-notrack schema=1'
umask 077
mkdir -p -- "$runtime"
exec 9>"$runtime/lock"
flock -x 9
snapshot=$(mktemp "$runtime/table.XXXXXX")
batch=$(mktemp "$runtime/batch.XXXXXX")
trap 'rm -f -- "$snapshot" "$batch"' EXIT

# Distinguish absence from netlink/permission errors before constructing a batch.
nft -j list tables >"$snapshot"
exists=$(jq -r --arg name "$table" '[.nftables[] | .table? | select(.family == "inet" and .name == $name)] | length' "$snapshot")
if [[ "$exists" != 0 ]]; then
  nft -j list table inet "$table" >"$snapshot"
  jq -e --arg name "$table" --arg owner "$owner" 'any(.nftables[]; .table? | .family == "inet" and .name == $name and .comment == $owner)' "$snapshot" >/dev/null || die "Table $table has a different owner; preserved."
fi

case "$action" in
  status)
    [[ "$exists" != 0 ]] || die 'API loopback exemption is not installed in the current network namespace.'
    nft list table inet "$table"
    ;;
  remove)
    if [[ "$exists" != 0 ]]; then nft delete table inet "$table"; fi
    printf 'API loopback exemption removed; existing TCP sockets are unchanged.\n'
    ;;
  apply)
    command -v conntrack >/dev/null || die 'Missing command: conntrack'
    [[ -r "$rules" ]] || die "Rules file is not readable: $rules"
    # Exempting an established tracked flow can strand its old conntrack entry
    # until the long established timeout. Drain clients first, never DELETE it.
    conntrack -L -f ipv4 -p tcp -s 127.0.0.1 -d 127.0.0.1 --dport 8080 >"$snapshot"
    if grep -Eq ' (ESTABLISHED|SYN_SENT|SYN_RECV) ' "$snapshot"; then
      die 'Tracked API loopback sockets are still active. Drain local API clients (including Vite) before applying; no rules were changed.'
    fi
    if [[ "$exists" != 0 ]]; then printf 'delete table inet %s\n' "$table" >"$batch"; fi
    cat -- "$rules" >>"$batch"
    nft --check --file "$batch"
    nft --file "$batch"
    printf 'IPv4 loopback API :8080 exemption applied in both directions.\n'
    ;;
esac
