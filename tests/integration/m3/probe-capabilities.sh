#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: sudo bash tests/integration/m3/probe-capabilities.sh [--isolated] [--evidence-dir DIR] [--output FILE]

Runs destructive packet probes only inside a temporary network namespace.
It never installs packages, changes the host ruleset, or starts production units.
Exit 0 = every probe passed, 1 = probe failed, 2 = prerequisite missing.
EOF
}

output=''
evidence_dir=''
while (($#)); do
  case "$1" in
    --isolated) shift ;;
    --evidence-dir) (($# >= 2)) || { usage >&2; exit 2; }; evidence_dir=$2; shift 2 ;;
    --output) (($# >= 2)) || { usage >&2; exit 2; }; output=$2; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo 'run as root' >&2; exit 2; }
for command_name in suricata nft ip ping tcpdump timeout jq sha256sum; do
  command -v "$command_name" >/dev/null 2>&1 || { echo "missing prerequisite: $command_name" >&2; exit 2; }
done

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_root=$(cd -- "$script_dir/../../.." && pwd)
ids_config=${NGFW_IDS_CONFIG:-/etc/ngfw/inspection/ids.yaml}
ips_config=${NGFW_IPS_CONFIG:-/etc/ngfw/inspection/ips.yaml}
[[ -r "$ids_config" ]] || ids_config="$project_root/deploy/inspection/ids.yaml"
[[ -r "$ips_config" ]] || ips_config="$project_root/deploy/inspection/ips.yaml"
[[ -r "$ids_config" && -r "$ips_config" ]] || { echo 'inspection YAML is unavailable' >&2; exit 2; }

namespace="ngfw-m3-cap-$$"
work=$(mktemp -d /tmp/ngfw-m3-cap.XXXXXX)
suricata_pid=''
cleanup() {
  set +e
  if [[ -n "$suricata_pid" ]]; then
    kill "$suricata_pid" 2>/dev/null
    wait "$suricata_pid" 2>/dev/null
  fi
  ip netns del "$namespace" 2>/dev/null
  rm -rf -- "$work"
}
trap cleanup EXIT INT TERM

build_info=$(suricata --build-info 2>&1)
grep -Eiq 'NFQ.*(yes|enabled)|NFQ support.*yes' <<<"$build_info" || { echo 'Suricata was built without NFQ support' >&2; exit 1; }
grep -Eiq 'NFLOG.*(yes|enabled)|NFLOG support.*yes' <<<"$build_info" || { echo 'Suricata was built without NFLOG support' >&2; exit 1; }
suricata -T -c "$ids_config" >"$work/ids-config-test.log" 2>&1 || { cat "$work/ids-config-test.log" >&2; exit 1; }
suricata -T -c "$ips_config" >"$work/ips-config-test.log" 2>&1 || { cat "$work/ips-config-test.log" >&2; exit 1; }

ip netns add "$namespace"
ip -n "$namespace" link set lo up

cat >"$work/schema.nft" <<'EOF'
table inet ngfw_inspection {
  set app_denied_v4 { typeof ct zone . ct id . ct original ip saddr . ct original proto-src . ct original ip daddr . ct original proto-dst . meta l4proto; flags timeout; timeout 60s; }
  set ips_ready { type nf_proto . inet_proto; flags timeout; }
  chain select_early { type filter hook output priority 0; policy accept; }
  chain enforce_late { type filter hook output priority 10; policy accept; }
}
EOF
ip netns exec "$namespace" nft -c -f "$work/schema.nft"
ip netns exec "$namespace" nft -f "$work/schema.nft"
ip netns exec "$namespace" nft add element inet ngfw_inspection ips_ready '{ ipv4 . tcp timeout 3s, ipv4 . udp timeout 3s }'
ip netns exec "$namespace" nft add element inet ngfw_inspection app_denied_v4 '{ 0 . 1 . 192.0.2.1 . 50000 . 198.51.100.1 . 443 . tcp timeout 60s }'
ip netns exec "$namespace" nft flush ruleset

# A later base chain DROP must override an earlier ACCEPT/cache-style result.
cat >"$work/priority.nft" <<'EOF'
table inet priority_probe {
  chain early { type filter hook output priority 0; policy accept; ip protocol icmp accept }
  chain late { type filter hook output priority 10; policy accept; ip protocol icmp drop }
}
EOF
ip netns exec "$namespace" nft -f "$work/priority.nft"
if ip netns exec "$namespace" ping -c 1 -W 1 127.0.0.1 >/dev/null 2>&1; then
  echo 'later base-chain DROP did not override earlier ACCEPT' >&2
  exit 1
fi
ip netns exec "$namespace" nft flush ruleset

# NFLOG group 100 must be observable in the same namespace.
ip netns exec "$namespace" nft add table inet nflog_probe
ip netns exec "$namespace" nft 'add chain inet nflog_probe output { type filter hook output priority 0; policy accept; }'
ip netns exec "$namespace" nft 'add rule inet nflog_probe output ip protocol icmp log group 100 accept'
ip netns exec "$namespace" timeout 5 tcpdump -nn -i nflog:100 -c 1 >"$work/nflog.log" 2>&1 &
tcpdump_pid=$!
sleep 0.3
ip netns exec "$namespace" ping -c 1 -W 1 127.0.0.1 >/dev/null
wait "$tcpdump_pid" || { cat "$work/nflog.log" >&2; echo 'NFLOG group 100 received no packet' >&2; exit 1; }
ip netns exec "$namespace" nft flush ruleset

# Queue bypass without a listener must preserve base ALLOW, while a later hard
# DROP must still win. These are the M3 fail-open and M1 invariant probes.
ip netns exec "$namespace" nft add table inet nfq_probe
ip netns exec "$namespace" nft 'add chain inet nfq_probe queue { type filter hook output priority 0; policy accept; }'
ip netns exec "$namespace" nft 'add rule inet nfq_probe queue ip protocol icmp queue num 100 bypass'
ip netns exec "$namespace" ping -c 1 -W 1 127.0.0.1 >/dev/null || { echo 'NFQUEUE bypass did not fail open' >&2; exit 1; }
ip netns exec "$namespace" nft 'add chain inet nfq_probe hard_block { type filter hook output priority 10; policy accept; }'
ip netns exec "$namespace" nft 'add rule inet nfq_probe hard_block ip protocol icmp drop'
if ip netns exec "$namespace" ping -c 1 -W 1 127.0.0.1 >/dev/null 2>&1; then
  echo 'hard block was bypassed by NFQUEUE fail-open' >&2
  exit 1
fi
ip netns exec "$namespace" nft flush ruleset

version=$(suricata --build-info 2>/dev/null | sed -n 's/^Suricata version //p' | head -n1)
[[ -n "$version" ]] || version=$(suricata -V 2>&1 | head -n1)
build_hash=$(printf '%s' "$build_info" | sha256sum | awk '{print $1}')
kernel=$(uname -r)
if [[ -z "$output" ]]; then
  if [[ -n "$evidence_dir" ]]; then
    output="$evidence_dir/compatibility.json"
  else
    output="$PWD/m3-capability-$(date -u +%Y%m%dT%H%M%SZ).json"
  fi
fi
mkdir -p -- "$(dirname -- "$output")"
jq -n \
  --arg version "$version" --arg hash "$build_hash" --arg kernel "$kernel" \
  '{schema_version:1,status:"PASS",target_os:"Ubuntu 24.04 LTS",suricata_version:$version,suricata_build_hash:$hash,kernel_release:$kernel,checks:{nflog_group_100:"PASS",nfqueue_100_bypass:"PASS",nfqueue_100_listener:"NOT_RUN",nfq_fail_open:"PASS_STATIC_AND_ABSENT_LISTENER",nft_compound_guard:"PASS",base_chain_priority:"PASS"},evidence:$ARGS.named}' >"$output"
printf 'M3 capability probes passed; evidence: %s\n' "$output"
printf 'NFQUEUE listener and saturation remain NOT_RUN until the full M3 traffic acceptance runner.\n'
