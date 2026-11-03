#!/usr/bin/env bash
set -Eeuo pipefail

# Give the engine exclusive ownership of its dataplane links. MGMT keeps its
# existing Netplan/networkd profile. No daemon is restarted by this helper.
config=''
root=/etc/systemd
apply=0
while (($#)); do
  case "$1" in
    --config) config=${2:?--config needs a path}; shift 2 ;;
    --root) root=${2:?--root needs a path}; shift 2 ;;
    --apply) apply=1; shift ;;
    *) echo 'Usage: configure-network-ownership.sh --config FILE [--root /etc/systemd] [--apply]' >&2; exit 2 ;;
  esac
done
[[ -n "$config" && -r "$config" ]] || { echo 'a readable --config file is required' >&2; exit 2; }

# Validate all names/modes before creating directories or replacing any file.
jq -e '(.config // .) | .interfaces | type == "array" and
  all(.[]; (.system_name | type == "string" and test("^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$")) and
    (.mode == "L3" or .mode == "VLAN_PARENT" or .mode == "VLAN_SUBINTERFACE" or .mode == "MANAGEMENT")) and
  ((map(.system_name) | unique | length) == length)' "$config" >/dev/null || {
  echo 'invalid/duplicate interface name or mode; no ownership files changed' >&2; exit 1;
}
names=$(jq -r '(.config // .).interfaces | map(select(.mode != "MANAGEMENT") | .system_name) | sort | join(" ")' "$config")
marker='# Managed by NGFW network ownership'
network_file="$root/network/05-ngfw-dataplane.network"
routing_file="$root/networkd.conf.d/90-ngfw-routing.conf"
for target in "$network_file" "$routing_file"; do
  if [[ -e "$target" ]] && ! grep -Fxq "$marker" "$target"; then
    printf 'refusing to overwrite non-NGFW file: %s\n' "$target" >&2
    exit 1
  fi
done

render_network() {
  printf '%s\n[Match]\nName=%s\n\n[Link]\nUnmanaged=yes\nRequiredForOnline=no\n' "$marker" "$names"
}
render_routing() {
  printf '%s\n[Network]\nManageForeignRoutes=no\nManageForeignRoutingPolicyRules=no\n' "$marker"
}
if [[ $apply -eq 0 ]]; then
  [[ -z "$names" ]] || render_network
  render_routing
  echo 'Preview only. Use --apply to install the displayed policy.'
  exit 0
fi

install -d -m 0755 "$root/network" "$root/networkd.conf.d"
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
if [[ -n "$names" ]]; then
  render_network >"$temporary/dataplane.network"
  install -m 0644 "$temporary/dataplane.network" "$network_file"
else
  rm -f -- "$network_file"
fi
render_routing >"$temporary/routing.conf"
install -m 0644 "$temporary/routing.conf" "$routing_file"
printf 'Installed engine network ownership for: %s\nMGMT profiles retained. Reload networkd link configuration; routing policy is read on networkd restart.\n' "${names:-none}"
