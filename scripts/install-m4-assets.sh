#!/usr/bin/env bash
set -Eeuo pipefail

# Installs M4 configuration and hardened units only. It intentionally does
# not install/start the legacy proxy binary or change the nftables ruleset.
[[ $EUID -eq 0 ]] || { echo 'run as root' >&2; exit 2; }
for command in install getent groupadd useradd usermod id cmp suricata runuser systemctl; do
  command -v "$command" >/dev/null 2>&1 || { echo "missing prerequisite: $command" >&2; exit 2; }
done
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
[[ -f "$repo/deploy/request-gate/suricata.yaml" ]] || { echo 'repository M4 assets missing' >&2; exit 2; }

getent group ngfw >/dev/null 2>&1 || { echo 'install M1/M2 ngfw account first' >&2; exit 2; }
getent group ngfw-proxy >/dev/null 2>&1 || groupadd --system ngfw-proxy
if ! id ngfw-proxy >/dev/null 2>&1; then
  useradd --system --gid ngfw-proxy --groups ngfw --home-dir /var/lib/ngfw --no-create-home --shell /usr/sbin/nologin ngfw-proxy
fi
id -nG ngfw-proxy | tr ' ' '\n' | grep -qx ngfw || usermod -a -G ngfw ngfw-proxy

install -d -o root -g ngfw-proxy -m 0750 /etc/ngfw/request-gate /etc/ngfw/request-gate/rules
install -d -o ngfw-proxy -g ngfw-proxy -m 0700 /var/lib/ngfw/ca /var/lib/ngfw/request-workers

copy_once() {
  local source=$1 target=$2 mode=$3 owner=$4 group=$5
  if [[ -e $target ]]; then
    cmp -s -- "$source" "$target" || { echo "existing asset differs; review manually: $target" >&2; exit 1; }
    return
  fi
  install -o "$owner" -g "$group" -m "$mode" -- "$source" "$target"
}
copy_once "$repo/deploy/request-gate/suricata.yaml" /etc/ngfw/request-gate/suricata.yaml 0640 root ngfw-proxy
copy_once "$repo/deploy/request-gate/rules/request-gate.rules" /etc/ngfw/request-gate/rules/request-gate.rules 0640 root ngfw-proxy
if [[ ! -e /etc/ngfw/proxy.env ]]; then
  install -o root -g ngfw-proxy -m 0640 "$repo/deploy/ngfw-proxy.env.example" /etc/ngfw/proxy.env
fi
copy_once "$repo/deploy/ngfw-proxy.service" /etc/systemd/system/ngfw-proxy.service 0644 root root
copy_once "$repo/deploy/ngfw-request-worker-preflight.service" /etc/systemd/system/ngfw-request-worker-preflight.service 0644 root root

if [[ -e /var/lib/ngfw/ca/ca.key ]] && runuser -u ngfw -- test -r /var/lib/ngfw/ca/ca.key; then
  echo 'CA private key is readable by the API account; migrate ownership/mode before enabling M4' >&2
  exit 1
fi
if [[ -e /var/lib/ngfw/ca/ca.key ]] && ! runuser -u ngfw-proxy -- test -r /var/lib/ngfw/ca/ca.key; then
  echo 'CA private key exists but the dedicated proxy account cannot read it; migrate owner/mode before enabling M4' >&2
  exit 1
fi
runuser -u ngfw-proxy -- suricata -T -c /etc/ngfw/request-gate/suricata.yaml -l /var/lib/ngfw/request-workers
systemctl daemon-reload
echo 'M4 assets installed and Suricata syntax checked. Proxy remains disabled pending T01/T06/T07/T28.'
