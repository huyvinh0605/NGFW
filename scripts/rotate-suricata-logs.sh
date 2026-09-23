#!/usr/bin/env bash
set -Eeuo pipefail

root=${NGFW_INSPECTION_ROOT:-/var/lib/ngfw/inspection}
rotate_bytes=${NGFW_EVE_ROTATE_BYTES:-33554432}
retention_bytes=${NGFW_INSPECTION_RETENTION_BYTES:-268435456}
retention_days=${NGFW_INSPECTION_RETENTION_DAYS:-1}
rotation_grace_seconds=${NGFW_EVE_ROTATION_GRACE_SECONDS:-120}
lock=/run/ngfw/inspection-retention.lock

case "$root" in
  /var/lib/ngfw/inspection|/var/lib/ngfw/inspection/) ;;
  *) printf 'refusing unmanaged inspection root: %s\n' "$root" >&2; exit 2 ;;
esac
[[ "$rotate_bytes" =~ ^[0-9]+$ && "$retention_bytes" =~ ^[0-9]+$ && "$retention_days" =~ ^[0-9]+$ && "$rotation_grace_seconds" =~ ^[0-9]+$ ]] || {
  echo 'retention limits must be non-negative integers' >&2
  exit 2
}

mkdir -p /run/ngfw
if ! mkdir "$lock" 2>/dev/null; then
  exit 0
fi
trap 'rmdir "$lock" 2>/dev/null || true' EXIT

rotate_sensor() {
  local mode=$1 directory="$root/$1" current="$root/$1/eve.json" pid_file="$root/$1/suricata.pid"
  [[ -d "$directory" ]] || return 0
  local size=0
  if [[ -f "$current" ]]; then
    size=$(stat -c '%s' -- "$current")
  fi
  (( size >= rotate_bytes )) || return 0
  local stamp rotated
  stamp=$(date -u +%Y%m%dT%H%M%S)
  rotated="$directory/eve.json.$stamp-$$"
  mv -- "$current" "$rotated"
  if [[ -r "$pid_file" ]]; then
    local pid
    pid=$(cat "$pid_file")
    if [[ "$pid" =~ ^[0-9]+$ ]] && [[ -r "/proc/$pid/comm" ]] && grep -qx 'Suricata-Main\|suricata' "/proc/$pid/comm"; then
      kill -HUP "$pid"
    fi
  fi
  printf 'rotated %s EVE to %s\n' "$mode" "$rotated"
}

rotate_sensor ids
rotate_sensor ips

prune_sensor() {
  local directory="$root/$1" total now candidate bytes modified
  [[ -d "$directory" ]] || return 0
  # Only files created by the launcher/rotator are eligible. Current EVE,
  # sockets, PID and epoch files are never selected.
  find "$directory" -maxdepth 1 -type f \( -name 'eve.json.*' -o -name 'fast.log.*' \) -mtime "+$retention_days" -delete
  total=$(du -sb -- "$directory" 2>/dev/null | awk '{print $1}')
  total=${total:-0}
  (( total > retention_bytes )) || return 0
  now=$(date +%s)
  while IFS= read -r candidate; do
    [[ -n "$candidate" && -f "$candidate" ]] || continue
    modified=$(stat -c '%Y' -- "$candidate")
    # The EVE reader may still hold the renamed file descriptor. Preserve a
    # bounded drain grace even when the byte target is temporarily exceeded.
    (( now - modified >= rotation_grace_seconds )) || continue
    bytes=$(stat -c '%s' -- "$candidate")
    rm -f -- "$candidate"
    (( total = total > bytes ? total - bytes : 0 ))
    (( total <= retention_bytes )) && break
  done < <(find "$directory" -maxdepth 1 -type f \( -name 'eve.json.*' -o -name 'fast.log.*' \) -printf '%T@ %p\n' | sort -n | cut -d' ' -f2-)
}

prune_sensor ids
prune_sensor ips
