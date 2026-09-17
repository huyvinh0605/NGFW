#!/usr/bin/env bash
set -Eeuo pipefail

# Read-only M2 preflight. Traffic scenarios are deliberately operator-driven:
# this script never flushes conntrack, changes nftables, or invents a verdict.
api_url="${NGFW_API_URL:-http://127.0.0.1:8080}"
token="${NGFW_API_TOKEN:-}"
engine_service="${NGFW_ENGINE_SERVICE:-ngfw-engine.service}"
api_service="${NGFW_API_SERVICE:-ngfw-api.service}"
socket_path="${NGFW_ENGINE_SOCKET:-/run/ngfw/engine.sock}"
state_dir="${NGFW_STATE_DIR:-/var/lib/ngfw}"

failures=0
check() {
  local description="$1"
  shift
  if "$@"; then
    printf 'PASS  %s\n' "$description"
  else
    printf 'FAIL  %s\n' "$description" >&2
    failures=$((failures + 1))
  fi
}

check "ngfw-engine is active" systemctl is-active --quiet "$engine_service"
check "ngfw-api is active" systemctl is-active --quiet "$api_service"
check "engine runtime socket exists" test -S "$socket_path"
check "IPv4 forwarding is enabled" test "$(sysctl -n net.ipv4.ip_forward)" = "1"
check "conntrack accounting is enabled" test "$(sysctl -n net.netfilter.nf_conntrack_acct 2>/dev/null || true)" = "1"
check "conntrack events are enabled" test "$(sysctl -n net.netfilter.nf_conntrack_events 2>/dev/null || true)" = "1"
check "conntrack timestamps are enabled" test "$(sysctl -n net.netfilter.nf_conntrack_timestamp 2>/dev/null || true)" = "1"
check "M2 epoch state is readable" test -r "$state_dir/runtime-epoch.json"
check "M2 runtime table is loaded" nft list table inet ngfw_runtime

engine_pid="$(systemctl show --property MainPID --value "$engine_service")"
api_pid="$(systemctl show --property MainPID --value "$api_service")"
api_caps="$(awk '/^CapEff:/ {print $2}' "/proc/$api_pid/status" 2>/dev/null || true)"
check "API has no effective capabilities" test "$api_caps" = "0000000000000000"

curl_args=(-fsS --max-time 5)
if [[ -n "$token" ]]; then
  curl_args+=(-H "Authorization: Bearer $token")
fi
probe_api() {
  local description="$1" output_file="$2" endpoint="$3"
  if curl "${curl_args[@]}" "$api_url$endpoint" >"$output_file"; then
    printf 'PASS  %s\n' "$description"
  else
    printf 'FAIL  %s\n' "$description" >&2
    failures=$((failures + 1))
  fi
}
probe_api "runtime health endpoint" /tmp/ngfw-m2-health.json /api/v1/health
probe_api "session API is bounded" /tmp/ngfw-m2-sessions.json '/api/v1/sessions?page=1&page_size=1'
probe_api "runtime stats endpoint" /tmp/ngfw-m2-stats.json /api/v1/stats/system

printf '\nEngine capabilities (informational):\n'
awk '/^CapEff:/ {print}' "/proc/$engine_pid/status" 2>/dev/null || true
printf '\nRuntime health/session samples (secrets excluded):\n'
cat /tmp/ngfw-m2-health.json /tmp/ngfw-m2-sessions.json /tmp/ngfw-m2-stats.json
printf '\nConntrack summary:\n'
conntrack -S || true

cat <<'EOF'

Next operator scenarios: run A-J in tests/integration/m2/README.md and save
conntrack, nft, API, journal and pcap evidence under evidence/m2/<run-id>.
EOF

if (( failures > 0 )); then
  printf '\n%d M2 preflight check(s) failed.\n' "$failures" >&2
  exit 1
fi
printf '\nM2 preflight passed; packet-path acceptance is still NOT_RUN.\n'
