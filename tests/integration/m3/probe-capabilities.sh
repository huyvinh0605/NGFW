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
for command_name in suricata nft ip ping tcpdump timeout jq sha256sum python3; do
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
tcpdump_pid=''
phase=build_support
stop_process() {
  local pid=$1
  [[ -n "$pid" ]] || return 0
  # A failed or interrupted saturation probe can leave the sensor SIGSTOPed.
  # Resume it before TERM so shutdown and log flushing can complete.
  kill -CONT "$pid" 2>/dev/null || true
  kill -TERM "$pid" 2>/dev/null || true
  for _ in $(seq 1 50); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  kill -KILL "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}
cleanup() {
  local exit_status=$?
  trap - EXIT INT TERM
  set +e
  stop_process "$tcpdump_pid"
  stop_process "$suricata_pid"
  ip netns del "$namespace" 2>/dev/null
  if [[ -n "$evidence_dir" && -d "$work" ]]; then
    mkdir -p -- "$evidence_dir/raw"
    cp -a -- "$work/." "$evidence_dir/raw/" 2>/dev/null || true
  fi
  if (( exit_status != 0 )) && [[ -n "${output:-$evidence_dir}" ]]; then
    local failure_output=${output:-$evidence_dir/compatibility.json}
    mkdir -p -- "$(dirname -- "$failure_output")"
    jq -n --arg phase "$phase" --argjson exit_code "$exit_status" \
      '{schema_version:1,status:"FAIL",phase:$phase,exit_code:$exit_code}' >"$failure_output"
  fi
  rm -rf -- "$work"
  exit "$exit_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

build_info=$(suricata --build-info 2>&1)
printf '%s\n' "$build_info" >"$work/suricata-build-info.txt"
nft --version >"$work/nft-version.txt"
uname -a >"$work/uname.txt"
grep -Eiq 'NFQ.*(yes|enabled)|NFQ support.*yes' <<<"$build_info" || { echo 'Suricata was built without NFQ support' >&2; exit 1; }
grep -Eiq 'NFLOG.*(yes|enabled)|NFLOG support.*yes' <<<"$build_info" || { echo 'Suricata was built without NFLOG support' >&2; exit 1; }
phase=ids_config
suricata -T -c "$ids_config" >"$work/ids-config-test.log" 2>&1 || { cat "$work/ids-config-test.log" >&2; exit 1; }
phase=ips_config
suricata -T -c "$ips_config" >"$work/ips-config-test.log" 2>&1 || { cat "$work/ips-config-test.log" >&2; exit 1; }

phase=nft_schema
ip netns add "$namespace"
ip -n "$namespace" link set lo up

# Kept byte-identical to dataplane.InspectionSchemaScript by a contract test.
# Probe the schema installed by the engine, including safe list/readback.
cat >"$work/schema.nft" <<'EOF'
table inet ngfw_inspection {
  comment "owner=ngfw-engine schema=2"
  map app_denied_v4 { typeof ct id : verdict; }
  set ips_ready { type nf_proto . inet_proto; flags timeout; timeout 3s; }
  chain guard { type filter hook forward priority -15; policy accept; meta l4proto { tcp, udp } ct id vmap @app_denied_v4; }
  chain inspect { type filter hook forward priority 10; policy accept; }
  chain select_original { }
  chain select_reply { }
}
EOF
ip netns exec "$namespace" nft -c -f "$work/schema.nft"
ip netns exec "$namespace" nft -f "$work/schema.nft"
cat >"$work/guard.nft" <<'EOF'
add set inet ngfw_inspection app_denied_z0_i1 { type ipv4_addr . inet_service . ipv4_addr . inet_service . inet_proto; flags timeout; timeout 60s; }
add chain inet ngfw_inspection app_guard_i1
add rule inet ngfw_inspection app_guard_i1 ct zone 0 ct original ip saddr . ct original proto-src . ct original ip daddr . ct original proto-dst . meta l4proto @app_denied_z0_i1 counter drop
add element inet ngfw_inspection app_denied_v4 { 1 : jump app_guard_i1 }
add element inet ngfw_inspection app_denied_z0_i1 { 192.0.2.1 . 50000 . 198.51.100.1 . 443 . tcp timeout 60s }
add element inet ngfw_inspection ips_ready { ipv4 . tcp timeout 3s, ipv4 . udp timeout 3s }
EOF
ip netns exec "$namespace" nft -c -f "$work/guard.nft"
ip netns exec "$namespace" nft -f "$work/guard.nft"
ip netns exec "$namespace" nft -j list table inet ngfw_inspection >"$work/schema-readback.json"
jq -e '[.nftables[] | .set? | select(.name == "app_denied_z0_i1") | .type] == [["ipv4_addr","inet_service","ipv4_addr","inet_service","inet_proto"]]' "$work/schema-readback.json" >/dev/null
ip netns exec "$namespace" nft 'get element inet ngfw_inspection app_denied_v4 { 1 }' >"$work/guard-dispatch-readback.txt"
ip netns exec "$namespace" nft 'get element inet ngfw_inspection app_denied_z0_i1 { 192.0.2.1 . 50000 . 198.51.100.1 . 443 . tcp }' >"$work/guard-tuple-readback.txt"
ip netns exec "$namespace" nft flush ruleset

# Run a real NFQUEUE listener with a private config/ruleset. The safe marker is
# ICMP echo in this isolated loopback-only namespace; no production interface,
# ruleset or EVE file is touched.
cat >"$work/probe.rules" <<'EOF'
drop icmp any any -> any any (msg:"NGFW isolated NFQUEUE marker"; itype:8; sid:9900199; rev:1;)
EOF
cat >"$work/nfq.yaml" <<EOF
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[127.0.0.0/8]"
    EXTERNAL_NET: "any"
default-rule-path: $work
rule-files:
  - probe.rules
# Suricata's packet pool requires at least 10 pending packets (NFQ depth 40).
max-pending-packets: 10
nfq:
  mode: accept
  fail-open: yes
stream:
  inline: yes
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: $work/nfq-eve.json
      types:
        - alert
        - stats:
            totals: yes
            threads: no
unix-command:
  enabled: yes
  filename: $work/nfq-control.sock
stats:
  enabled: yes
  interval: 1
logging:
  default-log-level: info
  outputs:
    - console:
        enabled: yes
EOF
phase=nfqueue_listener
suricata -T -c "$work/nfq.yaml" >"$work/nfq-config-test.log" 2>&1 || { cat "$work/nfq-config-test.log" >&2; exit 1; }
ip netns exec "$namespace" nft add table inet nfq_live
ip netns exec "$namespace" nft 'add chain inet nfq_live output { type filter hook output priority 0; policy accept; }'
ip netns exec "$namespace" nft 'add rule inet nfq_live output ip protocol icmp counter queue num 100 bypass'
ip netns exec "$namespace" suricata -c "$work/nfq.yaml" -q 100 --runmode workers --pidfile "$work/nfq.pid" >"$work/nfq-listener.log" 2>&1 &
suricata_pid=$!
for _ in $(seq 1 80); do
  [[ -S "$work/nfq-control.sock" ]] && break
  kill -0 "$suricata_pid" 2>/dev/null || { cat "$work/nfq-listener.log" >&2; echo 'NFQUEUE listener exited during startup' >&2; exit 1; }
  sleep 0.1
done
[[ -S "$work/nfq-control.sock" ]] || { cat "$work/nfq-listener.log" >&2; echo 'Suricata control socket was not created' >&2; exit 1; }
phase=unix_control_socket
python3 - "$work/nfq-control.sock" >"$work/control-probe.json" <<'PY' || { cat "$work/nfq-listener.log" >&2; exit 1; }
import json, socket, sys, time
path = sys.argv[1]
deadline = time.monotonic() + 5
while True:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    try:
        sock.connect(path)
        break
    except (FileNotFoundError, ConnectionRefusedError):
        sock.close()
        if time.monotonic() >= deadline:
            raise
        time.sleep(0.05)
decoder, buffered = json.JSONDecoder(), ""
def receive():
    global buffered
    while True:
        buffered = buffered.lstrip()
        try:
            reply, end = decoder.raw_decode(buffered)
            buffered = buffered[end:]
            return reply
        except json.JSONDecodeError:
            chunk = sock.recv(4096)
            if not chunk:
                raise RuntimeError("control socket closed before a complete JSON reply")
            buffered += chunk.decode("utf-8")
            if len(buffered) > 65536:
                raise RuntimeError("control socket reply exceeds 64 KiB")
# Suricata's version negotiation is JSON without a newline; commands use LF.
sock.sendall(b'{"version":"0.1"}')
greeting = receive()
if greeting.get("return") != "OK":
    raise SystemExit(1)
sock.sendall(b'{"command":"command-list"}\n')
reply = receive()
print(json.dumps({"greeting": greeting, "reply": reply}, sort_keys=True))
if reply.get("return") != "OK":
    raise SystemExit(1)
sock.close()
PY
phase=nfqueue_packet_drop
if ip netns exec "$namespace" ping -c 1 -W 1 127.0.0.1 >"$work/nfq-drop-ping.log" 2>&1; then
  echo 'live NFQUEUE listener did not drop the marker packet' >&2
  exit 1
fi
for _ in $(seq 1 30); do
  [[ -s "$work/nfq-eve.json" ]] && grep -q '9900199' "$work/nfq-eve.json" && break
  sleep 0.1
done
grep -q '9900199' "$work/nfq-eve.json" || { echo 'NFQUEUE marker produced no EVE alert' >&2; exit 1; }

# Distinguish a stalled listener from an absent listener. With a deliberately
# tiny pending queue and nfq.fail-open enabled, saturation must let at least
# some packets continue instead of deadlocking forwarding indefinitely.
phase=nfqueue_saturation
kill -STOP "$suricata_pid"
ip netns exec "$namespace" cat /proc/net/netfilter/nfnetlink_queue >"$work/nfq-before-saturation.txt"
set +e
# The sender must have enough socket credit for the pending NFQ packets.
# Otherwise ping hits its own send-buffer limit before the NFQ fills.
ip netns exec "$namespace" timeout 5 ping -S 1048576 -c 200 -i 0.001 -W 1 127.0.0.1 >"$work/nfq-saturation-ping.log" 2>&1
saturation_status=$?
set -e
ip netns exec "$namespace" cat /proc/net/netfilter/nfnetlink_queue >"$work/nfq-stalled-queue.txt"
kill -CONT "$suricata_pid"
received=$(sed -nE 's/.*, ([0-9]+) received.*/\1/p' "$work/nfq-saturation-ping.log" | tail -n1)
received=${received:-0}
if (( received == 0 )); then
  cat "$work/nfq-saturation-ping.log" >&2
  echo "NFQUEUE saturation did not demonstrate fail-open (ping exit $saturation_status)" >&2
  exit 1
fi
stop_process "$suricata_pid"
suricata_pid=''
phase=nfqueue_listener_exit_bypass
ip netns exec "$namespace" ping -c 1 -W 1 127.0.0.1 >"$work/nfq-after-listener.log" 2>&1 || { echo 'queue bypass failed after listener exit' >&2; exit 1; }
ip netns exec "$namespace" nft -j list ruleset >"$work/nft-live-probe.json"
ip netns exec "$namespace" nft flush ruleset

# A later base chain DROP must override an earlier ACCEPT/cache-style result.
phase=base_chain_priority
cat >"$work/priority.nft" <<'EOF'
table inet priority_probe {
  chain early { type filter hook output priority 0; policy accept; ip protocol icmp accept; }
  chain late { type filter hook output priority 10; policy accept; ip protocol icmp drop; }
}
EOF
ip netns exec "$namespace" nft -f "$work/priority.nft"
if ip netns exec "$namespace" ping -c 1 -W 1 127.0.0.1 >/dev/null 2>&1; then
  echo 'later base-chain DROP did not override earlier ACCEPT' >&2
  exit 1
fi
ip netns exec "$namespace" nft flush ruleset

# NFLOG group 100 must be observable in the same namespace.
phase=nflog_packet_capture
ip netns exec "$namespace" nft add table inet nflog_probe
ip netns exec "$namespace" nft 'add chain inet nflog_probe output { type filter hook output priority 0; policy accept; }'
ip netns exec "$namespace" nft 'add rule inet nflog_probe output ip protocol icmp log group 100 accept'
ip netns exec "$namespace" timeout 5 tcpdump -nn -i nflog:100 -c 1 >"$work/nflog.log" 2>&1 &
tcpdump_pid=$!
sleep 0.3
ip netns exec "$namespace" ping -c 1 -W 1 127.0.0.1 >/dev/null
wait "$tcpdump_pid" || { cat "$work/nflog.log" >&2; echo 'NFLOG group 100 received no packet' >&2; exit 1; }
tcpdump_pid=''
ip netns exec "$namespace" nft flush ruleset

# Queue bypass without a listener must preserve base ALLOW, while a later hard
# DROP must still win. These are the M3 fail-open and M1 invariant probes.
phase=base_deny_with_queue_bypass
ip netns exec "$namespace" nft add table inet nfq_probe
ip netns exec "$namespace" nft 'add chain inet nfq_probe queue_output { type filter hook output priority 0; policy accept; }'
ip netns exec "$namespace" nft 'add rule inet nfq_probe queue_output ip protocol icmp queue num 100 bypass'
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
  --argjson saturation_received "$received" \
  '{schema_version:1,status:"PASS",inspection_schema:2,target_os:"Ubuntu 24.04 LTS",suricata_version:$version,suricata_build_hash:$hash,kernel_release:$kernel,checks:{nflog_group_100:"PASS",nfqueue_100_bypass:"PASS",nfqueue_100_listener:"PASS",nfq_fail_open:"PASS_ABSENT_AND_SATURATED_LISTENER",unix_control_socket:"PASS",nft_compound_guard:"PASS",nft_guard_readback:"PASS",base_chain_priority:"PASS"},measurements:{saturation_echo_replies:$saturation_received}}' >"$output"
if [[ -n "$evidence_dir" ]]; then
  mkdir -p -- "$evidence_dir/raw"
  cp -a -- "$work/." "$evidence_dir/raw/"
fi
printf 'M3 capability probes passed; evidence: %s\n' "$output"
