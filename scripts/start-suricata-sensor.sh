#!/usr/bin/env bash
set -Eeuo pipefail

mode="${1:-}"
case "$mode" in
  ids|ips) ;;
  *) echo "usage: $0 ids|ips" >&2; exit 2 ;;
esac

suricata_binary="${NGFW_SURICATA_BINARY:-/usr/bin/suricata}"
config_root="${NGFW_INSPECTION_CONFIG_ROOT:-/etc/ngfw/inspection}"
runtime_root="${NGFW_INSPECTION_ROOT:-/var/lib/ngfw/inspection}"
config_path="$config_root/$mode.yaml"
runtime_path="$runtime_root/$mode"

if [[ ! -x "$suricata_binary" ]]; then
  echo "Suricata binary is unavailable: $suricata_binary" >&2
  exit 1
fi
if [[ ! -r "$config_path" ]]; then
  echo "Suricata configuration is unavailable: $config_path" >&2
  exit 1
fi

umask 0027
mkdir -p -- "$runtime_path"
chmod 0750 "$runtime_path"
rm -f -- "$runtime_path/control.sock"

# Keep records from different Suricata processes in separate source epochs.
# Rotate the old file before publishing the new epoch; ngfw-engine drains an
# already-open old descriptor and then starts the new file at offset zero.
if [[ -s "$runtime_path/eve.json" ]]; then
  rotation_stamp=$(date -u +%Y%m%dT%H%M%S)
  mv -- "$runtime_path/eve.json" "$runtime_path/eve.json.startup-$rotation_stamp-$$"
else
  rm -f -- "$runtime_path/eve.json"
fi
epoch=$(cat /proc/sys/kernel/random/uuid)
epoch_tmp=$(mktemp "$runtime_path/.sensor.epoch.XXXXXX")
printf '%s\n' "$epoch" > "$epoch_tmp"
chmod 0640 "$epoch_tmp"
mv -f -- "$epoch_tmp" "$runtime_path/sensor.epoch"

common_args=(
  -c "$config_path"
  --runmode workers
  --pidfile "$runtime_path/suricata.pid"
)

if [[ "$mode" == "ids" ]]; then
  exec "$suricata_binary" "${common_args[@]}" --nflog=100
fi
exec "$suricata_binary" "${common_args[@]}" -q 100
