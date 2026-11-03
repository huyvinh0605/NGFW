#!/usr/bin/env bash
set -Eeuo pipefail

# Installs M4 configuration, hardened units and optionally a built proxy.
# Kernel interception is owned exclusively by engine config activation.
[[ $EUID -eq 0 ]] || { echo 'run as root' >&2; exit 2; }
proxy_binary=''
if [[ ${1:-} == --proxy-binary && $# -eq 2 ]]; then
  proxy_binary=$2
  [[ -f $proxy_binary && -x $proxy_binary ]] || { echo 'proxy binary must be an executable regular file' >&2; exit 2; }
elif [[ $# -ne 0 ]]; then
  echo 'usage: install-m4-assets.sh [--proxy-binary /absolute/path/ngfw-proxy]' >&2
  exit 2
fi
for command in install getent groupadd useradd gpasswd id cmp suricata setpriv runuser systemctl setfacl mktemp cp grep tr; do
  command -v "$command" >/dev/null 2>&1 || { echo "missing prerequisite: $command" >&2; exit 2; }
done
if systemctl is-active --quiet ngfw-proxy.service; then
  echo 'stop ngfw-proxy before changing its account and unit; restart engine then proxy after installation' >&2
  exit 1
fi
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
[[ -f "$repo/deploy/request-gate/suricata.yaml" ]] || { echo 'repository M4 assets missing' >&2; exit 2; }

getent group ngfw >/dev/null 2>&1 || { echo 'install M1/M2 ngfw account first' >&2; exit 2; }
getent group ngfw-proxy >/dev/null 2>&1 || groupadd --system ngfw-proxy
if ! id ngfw-proxy >/dev/null 2>&1; then
  useradd --system --gid ngfw-proxy --home-dir /var/lib/ngfw --no-create-home --shell /usr/sbin/nologin ngfw-proxy
fi
# The ngfw group can read the management token, state and privileged IPC.
# Give the proxy search-only access to its private subdirectories instead.
setfacl -m u:ngfw-proxy:--x /etc/ngfw /var/lib/ngfw
if id -nG ngfw-proxy | tr ' ' '\n' | grep -qx ngfw; then
  gpasswd -d ngfw-proxy ngfw
fi
if id -nG ngfw-proxy | tr ' ' '\n' | grep -qx ngfw; then
  echo 'proxy account still belongs to the privileged ngfw group' >&2
  exit 1
fi

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
install_owned_unit() {
  local source=$1 target=$2 marker=$3 backup
  if [[ -e $target ]] && ! cmp -s -- "$source" "$target"; then
    grep -Fq -- "$marker" "$target" || { echo "refuse to replace unrecognized unit: $target" >&2; return 1; }
    backup=$(mktemp "${target}.backup.XXXXXX")
    cp -a -- "$target" "$backup"
    echo "saved previous unit: $backup"
  fi
  install -o root -g root -m 0644 -- "$source" "$target"
}
copy_once "$repo/deploy/request-gate/suricata.yaml" /etc/ngfw/request-gate/suricata.yaml 0640 root ngfw-proxy
copy_once "$repo/deploy/request-gate/rules/request-gate.rules" /etc/ngfw/request-gate/rules/request-gate.rules 0640 root ngfw-proxy
if [[ ! -e /etc/ngfw/proxy.env ]]; then
  install -o root -g ngfw-proxy -m 0640 "$repo/deploy/ngfw-proxy.env.example" /etc/ngfw/proxy.env
fi
install_owned_unit "$repo/deploy/ngfw-proxy.service" /etc/systemd/system/ngfw-proxy.service 'Description=NGFW selective HTTP/TLS request gate'
install_owned_unit "$repo/deploy/ngfw-request-worker-preflight.service" /etc/systemd/system/ngfw-request-worker-preflight.service 'Description=Validate NGFW M4 Suricata request-worker configuration'
install -d -o root -g root -m 0755 /etc/systemd/system/ngfw-engine.service.d
install_owned_unit "$repo/deploy/ngfw-engine-m4.conf" /etc/systemd/system/ngfw-engine.service.d/40-m4.conf 'SupplementaryGroups=ngfw-proxy'
if [[ -n $proxy_binary ]]; then
  install -d -o root -g root -m 0755 /usr/local/lib/ngfw
  install -o root -g root -m 0755 -- "$proxy_binary" /usr/local/lib/ngfw/ngfw-proxy
fi

if [[ -e /var/lib/ngfw/ca/ca.key ]] && runuser -u ngfw -- test -r /var/lib/ngfw/ca/ca.key; then
  echo 'CA private key is readable by the API account; migrate ownership/mode before enabling M4' >&2
  exit 1
fi
if [[ -e /var/lib/ngfw/ca/ca.key ]] && ! runuser -u ngfw-proxy -- test -r /var/lib/ngfw/ca/ca.key; then
  echo 'CA private key exists but the dedicated proxy account cannot read it; migrate owner/mode before enabling M4' >&2
  exit 1
fi
if [[ -e /etc/ngfw/ngfw.env ]] && runuser -u ngfw-proxy -- test -r /etc/ngfw/ngfw.env; then
  echo 'proxy can read the management environment/token' >&2
  exit 1
fi
if [[ -S /run/ngfw/engine.sock ]] && runuser -u ngfw-proxy -- test -w /run/ngfw/engine.sock; then
  echo 'proxy can access the privileged engine IPC socket' >&2
  exit 1
fi
for directory in /etc/ngfw /var/lib/ngfw; do
  if ! runuser -u ngfw-proxy -- test -x "$directory"; then
    echo "proxy lacks search-only access to $directory" >&2
    exit 1
  fi
  if runuser -u ngfw-proxy -- test -r "$directory"; then
    echo "proxy can list privileged parent directory $directory" >&2
    exit 1
  fi
done
runuser -u ngfw-proxy -- suricata -T -c /etc/ngfw/request-gate/suricata.yaml -l /var/lib/ngfw/request-workers
systemctl daemon-reload
echo 'M4 assets installed and Suricata syntax checked. Provision CA if needed, restart engine for socket-group membership, then enable/start ngfw-proxy before committing M4.'
