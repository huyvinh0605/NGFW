#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 [--evidence-dir DIR] [--pcap FILE] [--config-root DIR]" >&2
}

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_root=$(cd -- "$script_dir/../../.." && pwd)
evidence_dir=''
pcap="$project_root/tests/fixtures/m3/marker-http.pcap"
if [[ -r /usr/local/share/ngfw/inspection/marker-http.pcap ]]; then
  pcap=/usr/local/share/ngfw/inspection/marker-http.pcap
fi
config_root=${NGFW_INSPECTION_CONFIG_ROOT:-/etc/ngfw/inspection}
while (($#)); do
  case "$1" in
    --evidence-dir) (($# >= 2)) || { usage; exit 2; }; evidence_dir=$2; shift 2 ;;
    --pcap) (($# >= 2)) || { usage; exit 2; }; pcap=$2; shift 2 ;;
    --config-root) (($# >= 2)) || { usage; exit 2; }; config_root=$2; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

for command_name in suricata jq sha256sum; do
  command -v "$command_name" >/dev/null 2>&1 || { echo "missing prerequisite: $command_name" >&2; exit 2; }
done
[[ -r "$pcap" ]] || { echo "fixture PCAP is unavailable: $pcap" >&2; exit 2; }
if [[ ! -r "$config_root/ids.yaml" ]]; then
  config_root="$project_root/deploy/inspection"
fi
[[ -r "$config_root/ids.yaml" && -r "$config_root/ips.yaml" ]] || { echo 'inspection configs are unavailable' >&2; exit 2; }
rules_root="$config_root/rules"
[[ -d "$rules_root" ]] || rules_root="$config_root"
if [[ -z "$evidence_dir" ]]; then
  evidence_dir=$(mktemp -d /tmp/ngfw-m3-replay.XXXXXX)
else
  mkdir -p -- "$evidence_dir"
fi

sha256sum "$pcap" >"$evidence_dir/pcap.sha256"
suricata --build-info >"$evidence_dir/suricata-build-info.txt" 2>&1
for mode in ids ips; do
  output="$evidence_dir/$mode"
  mkdir -p -- "$output"
  suricata -T -c "$config_root/$mode.yaml" \
    --set "default-rule-path=$rules_root" \
    --set 'unix-command.enabled=no' >"$output/config-test.log" 2>&1
  suricata -r "$pcap" -c "$config_root/$mode.yaml" -l "$output" \
    --set "default-rule-path=$rules_root" \
    --set 'outputs.0.eve-log.filename=eve.json' \
    --set 'unix-command.enabled=no' \
    >"$output/replay.log" 2>&1
  [[ -s "$output/eve.json" ]] || { echo "$mode replay produced no EVE output" >&2; exit 1; }
  jq -e 'select(.event_type == "alert" and .alert.signature_id == 9900100)' "$output/eve.json" >"$output/marker-alert.json"
  jq -e 'select((.app_proto? == "http") or (.event_type == "http"))' "$output/eve.json" >"$output/http-observation.json"
done

jq -n --arg pcap "$(sha256sum "$pcap" | awk '{print $1}')" \
  '{status:"PASS",fixture_sha256:$pcap,ids_marker_sid:9900100,ips_marker_sid:9900100,inline_drop_proven:false,note:"Offline replay is not NFQUEUE acceptance."}' \
  >"$evidence_dir/result.json"
printf 'PASS M3 offline Suricata replay; evidence: %s\n' "$evidence_dir"
