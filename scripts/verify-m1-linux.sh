#!/usr/bin/env bash
set -euo pipefail

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
check "IPv4 forwarding is enabled now" test "$(sysctl -n net.ipv4.ip_forward)" = "1"
check "IPv4 forwarding is persisted" grep -Eq '^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=[[:space:]]*1([[:space:]]*(#.*)?)?$' /etc/sysctl.d/90-ngfw-ip-forward.conf
check "engine IPC socket exists" test -S "$socket_path"
check "engine IPC socket mode is 660" test "$(stat -c '%a' "$socket_path" 2>/dev/null || true)" = "660"
check "engine IPC socket group is ngfw" test "$(stat -c '%G' "$socket_path" 2>/dev/null || true)" = "ngfw"
check "managed nftables table is loaded" nft list table inet ngfw
check "dataplane applied snapshot exists" test -f "$state_dir/dataplane-applied.json"
check "no activation is left in progress" test ! -e "$state_dir/dataplane-applied.json.activation"

api_pid="$(systemctl show --property MainPID --value "$api_service")"
engine_pid="$(systemctl show --property MainPID --value "$engine_service")"
api_caps="$(awk '/^CapEff:/ {print $2}' "/proc/$api_pid/status" 2>/dev/null || true)"
engine_caps="$(awk '/^CapEff:/ {print $2}' "/proc/$engine_pid/status" 2>/dev/null || true)"
check "API has no effective Linux capabilities" test "$api_caps" = "0000000000000000"
engine_low_hex="${engine_caps: -4}"
check "engine has CAP_NET_ADMIN" bash -c '[[ $1 =~ ^[13579bdf][[:xdigit:]]{3}$ ]]' _ "$engine_low_hex"

if [[ -n "${NGFW_EXPECT_VLANS:-}" ]]; then
  for interface_name in $NGFW_EXPECT_VLANS; do
    check "VLAN $interface_name exists" ip -details link show dev "$interface_name"
  done
fi

printf '\nInterface state:\n'
ip -brief address
printf '\nRoute state:\n'
ip route show
printf '\nManaged nftables ruleset:\n'
nft list table inet ngfw

if (( failures > 0 )); then
  printf '\n%d M1 status check(s) failed.\n' "$failures" >&2
  exit 1
fi
printf '\nAll non-traffic M1 status checks passed. Packet-path acceptance tests are still required.\n'
