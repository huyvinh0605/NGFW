#!/usr/bin/env bash
set -Eeuo pipefail

# Read-only collection/preflight. A zero exit code means evidence collection
# succeeded, never that M4 network acceptance passed.
usage() {
  echo 'Usage: sudo bash scripts/verify-m4-linux.sh [--evidence-dir DIR]' >&2
}
evidence_dir=''
while (($#)); do
  case "$1" in
    --evidence-dir) (($# >= 2)) || { usage; exit 2; }; evidence_dir=$2; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
[[ $EUID -eq 0 ]] || { echo 'root required for nft and private-key permission checks' >&2; exit 2; }
for command in systemctl nft ip conntrack curl python3 runuser stat timeout id; do
  command -v "$command" >/dev/null 2>&1 || { echo "missing prerequisite: $command" >&2; exit 2; }
done
id ngfw >/dev/null 2>&1 || { echo 'M1/M2 ngfw API account is missing' >&2; exit 2; }
umask 077
if [[ -z $evidence_dir ]]; then
  evidence_dir=$(mktemp -d /tmp/ngfw-m4-verify.XXXXXX)
else
  mkdir -p -- "$evidence_dir"
  evidence_dir=$(cd -- "$evidence_dir" && pwd)
  chmod 0700 -- "$evidence_dir"
fi

date -u +'%Y-%m-%dT%H:%M:%SZ' > "$evidence_dir/collected-at.txt"
uname -a > "$evidence_dir/kernel.txt"
go version > "$evidence_dir/go-version.txt" 2>&1 || true
nft --version > "$evidence_dir/nft-version.txt" 2>&1 || true
suricata --build-info > "$evidence_dir/suricata-build.txt" 2>&1 || true
ip -brief address > "$evidence_dir/interfaces.txt" 2>&1 || true
nft -a list ruleset > "$evidence_dir/nft-ruleset.txt" 2>&1 || true
conntrack -L -o extended > "$evidence_dir/conntrack.txt" 2>&1 || true
systemctl show ngfw-engine.service ngfw-api.service ngfw-proxy.service ngfw-request-worker-preflight.service \
  -p Id -p ActiveState -p SubState -p User -p Group -p SupplementaryGroups \
  -p CapabilityBoundingSet -p AmbientCapabilities -p NoNewPrivileges \
  -p ProtectSystem -p ReadOnlyPaths -p ReadWritePaths > "$evidence_dir/units.txt" 2>&1 || true
systemctl show ngfw-proxy.service -p LoadState -p User -p Group -p CapabilityBoundingSet \
  -p AmbientCapabilities -p NoNewPrivileges -p ReadOnlyPaths -p ReadWritePaths \
  > "$evidence_dir/proxy-unit.txt" 2>&1 || true
for endpoint in health capabilities; do
  curl --silent --show-error --max-time 3 "http://127.0.0.1:8080/api/v1/request-gate/$endpoint" \
    > "$evidence_dir/$endpoint.json" 2> "$evidence_dir/$endpoint.err" || true
done
key=/var/lib/ngfw/ca/ca.key
if [[ -e $key ]]; then
  stat -c '%a %U:%G %n' /var/lib/ngfw/ca "$key" > "$evidence_dir/ca-permissions.txt"
  if runuser -u ngfw -- test -r "$key"; then echo true > "$evidence_dir/api-key-readable.txt"; else echo false > "$evidence_dir/api-key-readable.txt"; fi
  if runuser -u ngfw-proxy -- test -r "$key"; then echo true > "$evidence_dir/proxy-key-readable.txt"; else echo false > "$evidence_dir/proxy-key-readable.txt"; fi
else
  echo 'CA key absent' > "$evidence_dir/ca-permissions.txt"
  echo unknown > "$evidence_dir/api-key-readable.txt"
  echo unknown > "$evidence_dir/proxy-key-readable.txt"
fi
if [[ -f /etc/ngfw/request-gate/suricata.yaml ]] && id ngfw-proxy >/dev/null 2>&1; then
  timeout 30s runuser -u ngfw-proxy -- suricata -T -c /etc/ngfw/request-gate/suricata.yaml \
    -l /var/lib/ngfw/request-workers > "$evidence_dir/request-worker-preflight.txt" 2>&1 || true
else
  echo 'request-worker assets/account absent' > "$evidence_dir/request-worker-preflight.txt"
fi

python3 - "$evidence_dir" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
def load(name):
    try:
        value = json.loads((root / name).read_text())
        return value.get('data', {}) if value.get('success') else {}
    except (OSError, ValueError, AttributeError):
        return {}
def read(name):
    try: return (root / name).read_text().strip()
    except OSError: return 'unknown'
health, capabilities = load('health.json'), load('capabilities.json')
api_key = read('api-key-readable.txt')
proxy_key = read('proxy-key-readable.txt')
unit = read('proxy-unit.txt').lower()
unit_loaded = 'loadstate=loaded' in unit
unit_unsafe = 'cap_net_admin' in unit or ('user=ngfw-proxy' not in unit and unit_loaded)
ca_preflight = 'FAIL' if api_key == 'true' or proxy_key == 'false' else 'PENDING' if api_key == 'unknown' else 'PASS'
summary = {
    'acceptance_status': 'PENDING',
    'meaning': 'read-only collection only; M4-00..M4-42 require separate traffic evidence',
    'request_gate_health': health.get('status', 'unavailable'),
    'generation': health.get('generation'),
    'proxy_reachable': health.get('proxy_reachable', False),
    'production_ready': capabilities.get('production_ready', False),
    'api_can_read_ca_key': api_key,
    'proxy_can_read_ca_key': proxy_key,
    'ca_permission_preflight': ca_preflight,
    'proxy_unit_preflight': 'FAIL' if unit_unsafe else 'PASS' if unit_loaded else 'PENDING',
}
(root / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(summary, indent=2))
sys.exit(1 if ca_preflight == 'FAIL' or unit_unsafe else 0)
PY
echo "Evidence: $evidence_dir"
