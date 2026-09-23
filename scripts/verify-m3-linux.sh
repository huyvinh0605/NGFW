#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: sudo bash scripts/verify-m3-linux.sh [options]

Options:
  --preflight             Read-only non-traffic checks (default).
  --traffic               Run an explicitly selected lab scenario.
  --lab                   Confirm the target is an isolated lab.
  --topology FILE         Lab topology JSON used by traffic scenarios.
  --scenario ID           Acceptance matrix scenario ID (default: none).
  --evidence-dir DIR      Directory for raw evidence.
  --api-base URL          Management API base (default http://127.0.0.1:8080).
  --help                  Show this help.

Traffic mode never treats an unimplemented or unavailable harness as PASS.
EOF
}

mode=preflight
lab=0
topology=''
scenario=''
evidence_dir=''
api_base=${NGFW_API_BASE:-http://127.0.0.1:8080}
while (($#)); do
  case "$1" in
    --preflight) mode=preflight; shift ;;
    --traffic) mode=traffic; shift ;;
    --lab) lab=1; shift ;;
    --topology) (($# >= 2)) || { usage >&2; exit 2; }; topology=$2; shift 2 ;;
    --scenario) (($# >= 2)) || { usage >&2; exit 2; }; scenario=$2; shift 2 ;;
    --evidence-dir) (($# >= 2)) || { usage >&2; exit 2; }; evidence_dir=$2; shift 2 ;;
    --api-base) (($# >= 2)) || { usage >&2; exit 2; }; api_base=${2%/}; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo 'run as root so nft/conntrack evidence is complete' >&2; exit 2; }
for command_name in curl jq nft conntrack systemctl journalctl timeout; do
  command -v "$command_name" >/dev/null 2>&1 || { echo "missing prerequisite: $command_name" >&2; exit 2; }
done
if [[ -r /etc/ngfw/ngfw.env ]]; then
  set -a
  # shellcheck disable=SC1091
  . /etc/ngfw/ngfw.env
  set +a
fi

run_id=$(date -u +%Y%m%dT%H%M%SZ)-$$
if [[ -z "$evidence_dir" ]]; then
  evidence_dir="/tmp/ngfw-m3-$run_id"
fi
mkdir -p -- "$evidence_dir"
chmod 0700 "$evidence_dir"
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
auth=()
if [[ -n "${NGFW_API_TOKEN:-}" ]]; then
  auth=(-H "Authorization: Bearer $NGFW_API_TOKEN")
fi

api_get() {
  local path=$1 output=$2
  curl --silent --show-error --fail-with-body --connect-timeout 2 --max-time 5 \
    "${auth[@]}" -H 'Accept: application/json' "$api_base$path" >"$output"
}

collect_evidence() {
  local stage=$1 directory="$evidence_dir/$stage"
  mkdir -p -- "$directory"
  uname -a >"$directory/uname.txt"
  nft --version >"$directory/nft-version.txt" 2>&1 || true
  if command -v suricata >/dev/null 2>&1; then
    suricata --build-info >"$directory/suricata-build-info.txt" 2>&1 || true
  fi
  timeout 10 nft -j list ruleset >"$directory/nft-ruleset.json" 2>"$directory/nft-ruleset.err" || true
  timeout 10 conntrack -L -o extended,id >"$directory/conntrack.txt" 2>"$directory/conntrack.err" || true
  systemctl --no-pager --full status ngfw-engine ngfw-api ngfw-suricata-ids ngfw-suricata-ips >"$directory/systemd-status.txt" 2>&1 || true
  journalctl -u ngfw-engine -u ngfw-api -u ngfw-suricata-ids -u ngfw-suricata-ips --since "$started_at" --no-pager >"$directory/journal.txt" 2>&1 || true
  api_get /api/v1/health "$directory/api-health.json" || true
  api_get /api/v1/config "$directory/api-config.json" || true
  api_get /api/v1/sessions?page=1\&page_size=20 "$directory/api-sessions.json" || true
  api_get /api/v1/inspection/health "$directory/api-inspection-health.json" || true
  api_get /api/v1/inspection/capabilities "$directory/api-inspection-capabilities.json" || true
  api_get /api/v1/security/events?limit=20 "$directory/api-security-events.json" || true
  if [[ -r /etc/ngfw/inspection/manifest.json ]]; then
    cp -- /etc/ngfw/inspection/manifest.json "$directory/inspection-manifest.json"
  fi
}

fail() {
  local id=$1 reason=$2
  jq -n --arg id "$id" --arg reason "$reason" '{id:$id,status:"FAIL",reason:$reason}' >"$evidence_dir/assertion-$id.json"
  printf 'FAIL %s: %s\n' "$id" "$reason" >&2
  exit 1
}
pass() {
  local id=$1 reason=$2
  jq -n --arg id "$id" --arg reason "$reason" '{id:$id,status:"PASS",reason:$reason}' >"$evidence_dir/assertion-$id.json"
  printf 'PASS %s: %s\n' "$id" "$reason"
}
not_run() {
  local id=$1 reason=$2
  jq -n --arg id "$id" --arg reason "$reason" '{id:$id,status:"NOT_RUN",reason:$reason}' >"$evidence_dir/assertion-$id.json"
  printf 'NOT_RUN %s: %s\n' "$id" "$reason" >&2
  exit 2
}

collect_evidence before
systemctl is-active --quiet ngfw-engine || fail M3-PREFLIGHT 'ngfw-engine is not active'
systemctl is-active --quiet ngfw-api || fail M3-PREFLIGHT 'ngfw-api is not active'
api_get /api/v1/health "$evidence_dir/health.json" || fail M3-PREFLIGHT 'health endpoint failed'
jq -e '.success == true and (.data.status == "healthy" or .data.status == "degraded")' "$evidence_dir/health.json" >/dev/null || fail M3-PREFLIGHT 'invalid health envelope'
api_get /api/v1/inspection/capabilities "$evidence_dir/capabilities.json" || fail M3-PREFLIGHT 'capability endpoint failed'
jq -e '.success == true and .data.supported == true and (.data.modes | index("IDS")) != null and (.data.modes | index("IPS")) != null and (.data.fail_modes == ["OPEN"])' "$evidence_dir/capabilities.json" >/dev/null || fail M3-PREFLIGHT 'M3 capabilities are incomplete or advertise unsupported fail modes'
api_get /api/v1/inspection/health "$evidence_dir/inspection-health.json" || fail M3-PREFLIGHT 'inspection health endpoint failed'
jq -e '.success == true and (.data.status | type == "string") and (.data.sources | type == "object")' "$evidence_dir/inspection-health.json" >/dev/null || fail M3-PREFLIGHT 'invalid inspection health envelope'
api_get '/api/v1/security/events?limit=1' "$evidence_dir/security-page.json" || fail M3-PREFLIGHT 'security event pagination failed'
jq -e '.success == true and (.data.items | type == "array") and (.data.next_sequence | type == "number")' "$evidence_dir/security-page.json" >/dev/null || fail M3-PREFLIGHT 'invalid security event page'
status=$(curl --silent --output "$evidence_dir/invalid-filter.json" --write-out '%{http_code}' --connect-timeout 2 --max-time 5 "${auth[@]}" "$api_base/api/v1/security/events?limit=9999")
[[ "$status" == 400 ]] || fail M3-PREFLIGHT "invalid security filter returned HTTP $status instead of 400"

api_get /api/v1/config "$evidence_dir/config.json" || fail M3-PREFLIGHT 'running configuration endpoint failed'
uses_m3=$(jq -r '[.data.running.security_profiles[]?.inspection?.mode | select(. == "IDS" or . == "IPS")] | length > 0 or (.data.running.inspection.enabled // false)' "$evidence_dir/config.json")
if [[ "$uses_m3" == true ]]; then
  nft list table inet ngfw_inspection >"$evidence_dir/ngfw-inspection.nft" 2>&1 || fail M3-PREFLIGHT 'running M3 config has no ngfw_inspection nft table'
  jq -e '.data.enabled == true' "$evidence_dir/inspection-health.json" >/dev/null || fail M3-PREFLIGHT 'running M3 config has no inspection coordinator'
fi
pass M3-PREFLIGHT 'engine IPC v3, REST contracts and M3 runtime state are readable'

if [[ "$mode" == preflight ]]; then
  collect_evidence after
  printf 'Preflight completed. This is not packet-path acceptance. Evidence: %s\n' "$evidence_dir"
  exit 0
fi

[[ $lab -eq 1 ]] || not_run "${scenario:-M3-TRAFFIC}" '--traffic requires explicit --lab'
[[ -n "$scenario" ]] || not_run M3-TRAFFIC '--scenario is required; all is never implicit'
[[ -n "$topology" && -r "$topology" ]] || not_run "$scenario" 'topology JSON is missing'
jq -e 'type == "object" and (.wan != null) and (.lan != null) and (.dmz != null) and (.mgmt != null)' "$topology" >/dev/null || not_run "$scenario" 'topology must define wan, lan, dmz and mgmt'

case "$scenario" in
  M3-00)
    /usr/local/lib/ngfw/verify-m1-linux.sh >"$evidence_dir/m1-baseline.txt" 2>&1 || fail M3-00 'M1 baseline verification failed'
    /usr/local/lib/ngfw/verify-m2-linux.sh >"$evidence_dir/m2-baseline.txt" 2>&1 || fail M3-00 'M2 baseline verification failed'
    pass M3-00 'M1/M2 non-traffic baseline remains healthy'
    ;;
  *)
    not_run "$scenario" 'scenario needs the external LAN/WAN/DMZ traffic harness described in tests/integration/m3/README.md; no packet was generated, so it cannot be marked PASS'
    ;;
esac

collect_evidence after
