#!/usr/bin/env bash
set -Eeuo pipefail

# Install and build the M1/M2 appliance on Ubuntu 24.04. M3 Suricata sensor
# dependencies and units are opt-in through --with-inspection.

usage() {
  cat <<'EOF'
Usage: sudo bash scripts/install-linux.sh [options]

Options:
  --config FILE   Copy FILE to /etc/ngfw/lab.json when installing.
  --start         Enable and start ngfw-engine and ngfw-api after installation.
  --with-inspection
                  Install Suricata M3 assets and (with --start) start IDS/IPS
                  sensors. This never changes the selected Running config.
  --skip-apt      Do not run apt-get. Use this only when dependencies are already installed.
  --help          Show this help.

Environment:
  NGFW_API_TOKEN       Token written to a new /etc/ngfw/ngfw.env.
  NGFW_API_ADDR        API listen address written to a new env file (default :8080).
  NGFW_SKIP_OS_CHECK   Set to 1 to allow Ubuntu versions other than 24.04.
  NGFW_SKIP_TESTS      Set to 1 to skip the Go unit tests before installing binaries.
EOF
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

info() {
  printf '\n==> %s\n' "$*"
}

start_services=0
skip_apt=0
with_inspection=0
config_source=''
config_was_explicit=0

while (($# > 0)); do
  case "$1" in
    --config)
      (($# >= 2)) || die "--config requires a file path"
      config_source=$2
      config_was_explicit=1
      shift 2
      ;;
    --start)
      start_services=1
      shift
      ;;
    --skip-apt)
      skip_apt=1
      shift
      ;;
    --with-inspection)
      with_inspection=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1 (use --help)"
      ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run as root, for example: sudo bash scripts/install-linux.sh"

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_root=$(cd -- "$script_dir/.." && pwd)
cd "$project_root"

if [[ ! -f go.mod || ! -d cmd/ngfw-engine || ! -d cmd/ngfw-api ]]; then
  die "run this script from a complete NGFW source tree"
fi

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  if [[ "${ID:-}" != "ubuntu" ]]; then
    die "this installer targets Ubuntu; detected ${ID:-unknown}"
  fi
  if [[ "${VERSION_ID:-}" != "24.04" && "${NGFW_SKIP_OS_CHECK:-0}" != "1" ]]; then
    die "Ubuntu 24.04 is required (detected ${VERSION_ID:-unknown}); set NGFW_SKIP_OS_CHECK=1 to override"
  fi
else
  die "cannot identify the Linux distribution (/etc/os-release is missing)"
fi

if [[ $skip_apt -eq 0 ]]; then
  info "Installing Ubuntu dependencies"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  packages=(
    ca-certificates \
    conntrack \
    curl \
    gcc \
    golang-go \
    iproute2 \
    jq \
    make \
    nftables \
    openssl \
    iputils-ping \
    procps \
    tcpdump
  )
  if [[ $with_inspection -eq 1 ]]; then
    packages+=(suricata)
  fi
  apt-get install -y --no-install-recommends "${packages[@]}"
fi

required_commands=(go ip nft sysctl systemctl curl jq tcpdump conntrack openssl)
if [[ $with_inspection -eq 1 ]]; then
  required_commands+=(suricata sha256sum)
fi
for command_name in "${required_commands[@]}"; do
  command -v "$command_name" >/dev/null 2>&1 || die "required command is missing: $command_name"
done

go_version=$(go version | awk '{print $3}' | sed -E 's/^go//; s/[-+].*$//')
dpkg --compare-versions "$go_version" ge 1.22 || die "Go 1.22 or newer is required (found $go_version)"

if [[ -z "$config_source" ]]; then
  # The engine runtime is M2 L3/L4-only. Keep the general lab fixture for
  # later inspection milestones, but make a fresh appliance start with the
  # explicitly M2-compatible topology.
  config_source="$project_root/configs/examples/m2-lab.json"
elif [[ "$config_source" != /* ]]; then
  config_source="$project_root/$config_source"
fi
[[ -f "$config_source" ]] || die "configuration source does not exist: $config_source"

info "Preparing build"
build_dir=$(mktemp -d /tmp/ngfw-build.XXXXXX)
cleanup() {
  rm -rf -- "$build_dir"
}
trap cleanup EXIT

export GOTOOLCHAIN=local
go mod download
if [[ "${NGFW_SKIP_TESTS:-0}" != "1" ]]; then
  info "Running M1/M2/M3 unit tests"
  go test -count=1 ./...
fi

info "Building NGFW engine and management API"
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$build_dir/ngfw-engine" ./cmd/ngfw-engine
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$build_dir/ngfw-api" ./cmd/ngfw-api

info "Creating service account and directories"
getent group ngfw >/dev/null 2>&1 || groupadd --system ngfw
if ! id ngfw >/dev/null 2>&1; then
  useradd --system --gid ngfw --home-dir /var/lib/ngfw --create-home --shell /usr/sbin/nologin ngfw
fi
if [[ $with_inspection -eq 1 ]]; then
  getent group ngfw-inspect >/dev/null 2>&1 || groupadd --system ngfw-inspect
  if ! id ngfw-inspect >/dev/null 2>&1; then
    useradd --system --gid ngfw-inspect --home-dir /var/lib/ngfw/inspection --no-create-home --shell /usr/sbin/nologin ngfw-inspect
  fi
fi
install -d -o root -g ngfw -m 0750 /etc/ngfw
install -d -m 0755 /usr/local/lib/ngfw /usr/local/libexec/ngfw /usr/local/share/ngfw/examples /usr/local/share/ngfw/inspection
# The engine owns the running configuration, journal and epoch state. The API
# receives read access through the ngfw group and writes only its management
# candidate/auth data under the separate management directory.
install -d -o root -g ngfw -m 0750 /var/lib/ngfw
install -d -o ngfw -g ngfw -m 0770 /var/lib/ngfw/management /var/log/ngfw
if [[ $with_inspection -eq 1 ]]; then
  install -d -o root -g ngfw-inspect -m 0750 /etc/ngfw/inspection /etc/ngfw/inspection/rules
  install -d -o root -g ngfw-inspect -m 0750 /var/lib/ngfw/inspection
  install -d -o ngfw-inspect -g ngfw-inspect -m 0750 /var/lib/ngfw/inspection/ids /var/lib/ngfw/inspection/ips
fi

info "Installing binaries, examples and systemd units"
install -o root -g root -m 0755 "$build_dir/ngfw-engine" /usr/local/lib/ngfw/ngfw-engine
install -o root -g root -m 0755 "$build_dir/ngfw-api" /usr/local/lib/ngfw/ngfw-api
install -o root -g root -m 0755 scripts/verify-m1-linux.sh /usr/local/lib/ngfw/verify-m1-linux.sh
install -o root -g root -m 0755 scripts/verify-m2-linux.sh /usr/local/lib/ngfw/verify-m2-linux.sh
install -o root -g root -m 0644 configs/examples/*.json /usr/local/share/ngfw/examples/
install -o root -g root -m 0644 deploy/ngfw-engine.service deploy/ngfw-api.service /etc/systemd/system/
install -o root -g root -m 0644 deploy/90-ngfw-ip-forward.conf /etc/sysctl.d/90-ngfw-ip-forward.conf
install -o root -g root -m 0644 deploy/91-ngfw-conntrack.conf /etc/sysctl.d/91-ngfw-conntrack.conf

if [[ $with_inspection -eq 1 ]]; then
  info "Installing opt-in M3 inspection assets"
  install -o root -g root -m 0755 scripts/start-suricata-sensor.sh /usr/local/libexec/ngfw/start-suricata-sensor.sh
  install -o root -g root -m 0755 scripts/rotate-suricata-logs.sh /usr/local/libexec/ngfw/rotate-suricata-logs.sh
  install -o root -g root -m 0755 tests/integration/m3/probe-capabilities.sh /usr/local/lib/ngfw/probe-m3-capabilities.sh
  install -o root -g root -m 0755 tests/integration/m3/replay-suricata.sh /usr/local/lib/ngfw/replay-m3-suricata.sh
  install -o root -g root -m 0644 tests/fixtures/m3/marker-http.pcap tests/fixtures/m3/SHA256SUMS /usr/local/share/ngfw/inspection/
  if [[ -f scripts/verify-m3-linux.sh ]]; then
    install -o root -g root -m 0755 scripts/verify-m3-linux.sh /usr/local/lib/ngfw/verify-m3-linux.sh
  fi
  install -o root -g root -m 0644 \
    deploy/ngfw-suricata-ids.service \
    deploy/ngfw-suricata-ips.service \
    deploy/ngfw-suricata-retention.service \
    deploy/ngfw-suricata-retention.timer \
    /etc/systemd/system/
  install -d -o root -g root -m 0755 /etc/systemd/system/ngfw-engine.service.d
  install -o root -g root -m 0644 deploy/ngfw-engine-inspection.conf /etc/systemd/system/ngfw-engine.service.d/inspection.conf

  install_if_missing() {
    local source=$1 target=$2 mode=${3:-0644}
    if [[ -e "$target" ]]; then
      printf 'Preserving existing inspection asset: %s\n' "$target"
    else
      install -o root -g ngfw-inspect -m "$mode" "$source" "$target"
    fi
  }
  home_net_config=$config_source
  if [[ $config_was_explicit -eq 0 && -r /etc/ngfw/lab.json ]]; then
    home_net_config=/etc/ngfw/lab.json
  fi
  home_net=$(jq -er '[.interfaces[]? | select(.admin_state != false and .zone_id != "wan") | .ipv4_addresses[]? | select(type == "string" and (contains(":" ) | not))] | unique | if length == 0 then "any" else "[" + join(",") + "]" end' "$home_net_config") || die "cannot derive Suricata HOME_NET from $home_net_config"
  rendered_ids="$build_dir/ids.yaml"
  rendered_ips="$build_dir/ips.yaml"
  sed "s|HOME_NET: \"any\"|HOME_NET: \"$home_net\"|" deploy/inspection/ids.yaml >"$rendered_ids"
  sed "s|HOME_NET: \"any\"|HOME_NET: \"$home_net\"|" deploy/inspection/ips.yaml >"$rendered_ips"
  install_if_missing "$rendered_ids" /etc/ngfw/inspection/ids.yaml
  install_if_missing "$rendered_ips" /etc/ngfw/inspection/ips.yaml
  install_if_missing deploy/inspection/app-discovery.rules /etc/ngfw/inspection/rules/app-discovery.rules
  install_if_missing deploy/inspection/ids-demo.rules /etc/ngfw/inspection/rules/ids-demo.rules
  install_if_missing deploy/inspection/ips-demo.rules /etc/ngfw/inspection/rules/ips-demo.rules

  ids_hash=$(sha256sum /etc/ngfw/inspection/ids.yaml /etc/ngfw/inspection/rules/app-discovery.rules /etc/ngfw/inspection/rules/ids-demo.rules | sha256sum | awk '{print $1}')
  ips_hash=$(sha256sum /etc/ngfw/inspection/ips.yaml /etc/ngfw/inspection/rules/app-discovery.rules /etc/ngfw/inspection/rules/ips-demo.rules | sha256sum | awk '{print $1}')
  install_epoch=$(cat /proc/sys/kernel/random/uuid)
  manifest_tmp=$(mktemp /etc/ngfw/inspection/.manifest.XXXXXX)
  jq -n --arg ids_hash "$ids_hash" --arg ips_hash "$ips_hash" --arg epoch "$install_epoch" '{
    version: 1,
    managed_root: "/var/lib/ngfw/inspection",
    sensors: [
      {id:"ids",mode:"IDS",epoch:("install-"+$epoch+"-ids"),epoch_path:"/var/lib/ngfw/inspection/ids/sensor.epoch",config_hash:$ids_hash,ruleset_id:"m3-builtin-v1",eve_path:"/var/lib/ngfw/inspection/ids/eve.json",control_socket:"/var/lib/ngfw/inspection/ids/control.sock",service_unit:"ngfw-suricata-ids.service",discovery_sids:[9900001,9900002,9900003,9900004]},
      {id:"ips",mode:"IPS",epoch:("install-"+$epoch+"-ips"),epoch_path:"/var/lib/ngfw/inspection/ips/sensor.epoch",config_hash:$ips_hash,ruleset_id:"m3-builtin-v1",eve_path:"/var/lib/ngfw/inspection/ips/eve.json",control_socket:"/var/lib/ngfw/inspection/ips/control.sock",service_unit:"ngfw-suricata-ips.service",discovery_sids:[9900001,9900002,9900003,9900004]}
    ]
  }' >"$manifest_tmp"
  chown root:ngfw-inspect "$manifest_tmp"
  chmod 0640 "$manifest_tmp"
  mv -f -- "$manifest_tmp" /etc/ngfw/inspection/manifest.json

  suricata -T -c /etc/ngfw/inspection/ids.yaml || die "Suricata rejected /etc/ngfw/inspection/ids.yaml"
  suricata -T -c /etc/ngfw/inspection/ips.yaml || die "Suricata rejected /etc/ngfw/inspection/ips.yaml"
  /usr/local/lib/ngfw/replay-m3-suricata.sh --evidence-dir /var/lib/ngfw/inspection/install-replay || die "Suricata offline marker replay failed"
fi

config_target=/etc/ngfw/lab.json
if [[ -f "$config_target" && $config_was_explicit -eq 1 ]]; then
  backup_target="$config_target.bak.$(date -u +%Y%m%d%H%M%S)"
  cp -a -- "$config_target" "$backup_target"
  install -o root -g ngfw -m 0640 "$config_source" "$config_target"
  printf 'Replaced configuration from --config; previous file is backed up at %s\n' "$backup_target"
elif [[ -f "$config_target" ]]; then
  printf 'Preserving existing configuration: %s\n' "$config_target"
else
  install -o root -g ngfw -m 0640 "$config_source" "$config_target"
fi

env_file=/etc/ngfw/ngfw.env
if [[ -f "$env_file" ]]; then
  printf 'Preserving existing environment file: %s\n' "$env_file"
else
  api_token=${NGFW_API_TOKEN:-}
  if [[ -z "$api_token" ]]; then
    api_token=$(openssl rand -hex 32)
  fi
  api_addr=${NGFW_API_ADDR:-:8080}
  umask 0077
  {
    printf '%s\n' '# Generated by scripts/install-linux.sh; review before starting services.'
    printf 'NGFW_STATE_DIR=%s\n' '/var/lib/ngfw'
    printf 'NGFW_API_STATE_DIR=%s\n' '/var/lib/ngfw/management'
    printf 'NGFW_CONFIG=%s\n' "$config_target"
    printf 'NGFW_ENGINE_SOCKET=%s\n' '/run/ngfw/engine.sock'
    printf 'NGFW_IP_BINARY=%s\n' "$(command -v ip)"
    printf 'NGFW_NFT_BINARY=%s\n' "$(command -v nft)"
	if [[ $with_inspection -eq 1 ]]; then
	  printf 'NGFW_INSPECTION_MANIFEST=%s\n' '/etc/ngfw/inspection/manifest.json'
	  printf 'NGFW_INSPECTION_ROOT=%s\n' '/var/lib/ngfw/inspection'
	  printf 'NGFW_SURICATA_BINARY=%s\n' "$(command -v suricata)"
	fi
    printf 'NGFW_API_ADDR=%s\n' "$api_addr"
    printf 'NGFW_API_TOKEN=%s\n' "$api_token"
  } > "$env_file"
  chown root:ngfw "$env_file"
  chmod 0640 "$env_file"
fi

chown root:ngfw /var/lib/ngfw
chmod 0750 /var/lib/ngfw
chown ngfw:ngfw /var/lib/ngfw/management /var/log/ngfw
chmod 0770 /var/lib/ngfw/management /var/log/ngfw
if [[ $with_inspection -eq 1 ]]; then
  chown root:ngfw-inspect /var/lib/ngfw/inspection
  chmod 0750 /var/lib/ngfw/inspection
  chown ngfw-inspect:ngfw-inspect /var/lib/ngfw/inspection/ids /var/lib/ngfw/inspection/ips
  chmod 0750 /var/lib/ngfw/inspection/ids /var/lib/ngfw/inspection/ips
fi

info "Enabling IPv4 forwarding"
if ! sysctl --system >/dev/null; then
  printf 'WARNING: sysctl --system reported an error; checking the required value.\n' >&2
fi
[[ "$(sysctl -n net.ipv4.ip_forward)" == "1" ]] || die "net.ipv4.ip_forward is not 1 after applying /etc/sysctl.d/90-ngfw-ip-forward.conf"
for conntrack_key in net.netfilter.nf_conntrack_acct net.netfilter.nf_conntrack_events net.netfilter.nf_conntrack_timestamp; do
  if [[ "$(sysctl -n "$conntrack_key" 2>/dev/null || true)" != "1" ]]; then
    printf 'WARNING: %s is unavailable or not enabled; M2 session metadata will be degraded until the kernel setting is available.\n' "$conntrack_key" >&2
  fi
done

systemctl daemon-reload

if [[ $start_services -eq 1 ]]; then
  info "Starting NGFW services"
  systemctl enable ngfw-engine.service ngfw-api.service
  if [[ $with_inspection -eq 1 ]]; then
    systemctl enable ngfw-suricata-ids.service ngfw-suricata-ips.service ngfw-suricata-retention.timer
    systemctl restart ngfw-suricata-ids.service
    systemctl restart ngfw-suricata-ips.service
    systemctl restart ngfw-suricata-retention.timer
    systemctl is-active --quiet ngfw-suricata-ids.service || {
      systemctl --no-pager --full status ngfw-suricata-ids.service || true
      die "Suricata IDS sensor is not active"
    }
    systemctl is-active --quiet ngfw-suricata-ips.service || {
      systemctl --no-pager --full status ngfw-suricata-ips.service || true
      die "Suricata IPS sensor is not active"
    }
  fi
  systemctl restart ngfw-engine.service
  for _ in {1..40}; do
    [[ -S /run/ngfw/engine.sock ]] && break
    sleep 0.25
  done
  [[ -S /run/ngfw/engine.sock ]] || {
    systemctl --no-pager --full status ngfw-engine.service || true
    die "ngfw-engine did not create /run/ngfw/engine.sock; check the config and journal"
  }
  systemctl restart ngfw-api.service
  sleep 1
  systemctl is-active --quiet ngfw-engine.service || {
    systemctl --no-pager --full status ngfw-engine.service || true
    die "ngfw-engine is not active"
  }
  systemctl is-active --quiet ngfw-api.service || {
    systemctl --no-pager --full status ngfw-api.service || true
    die "ngfw-api is not active"
  }
  printf '\nNon-traffic M1/M2 checks:\n'
  # Use the same paths as the systemd units when the operator customized the
  # environment file. The file is root-owned and was created/approved above.
  set -a
  # shellcheck disable=SC1091
  . "$env_file"
  set +a
  # Run the installed copies. The source tree may have lost executable mode
  # when it was copied from Windows or extracted from an archive, while the
  # install commands above explicitly set 0755 on these files.
  /usr/local/lib/ngfw/verify-m1-linux.sh || die "M1 status checks failed; inspect the service journal"
  /usr/local/lib/ngfw/verify-m2-linux.sh || die "M2 preflight checks failed; inspect the service journal"
  if [[ $with_inspection -eq 1 && -x /usr/local/lib/ngfw/verify-m3-linux.sh ]]; then
    /usr/local/lib/ngfw/verify-m3-linux.sh --preflight || die "M3 preflight checks failed; inspect sensor and engine journals"
  fi
else
  printf '\nInstallation complete. Services were not started.\n'
  printf '1. Review %s and replace sample interface names, addresses and gateways.\n' "$config_target"
  printf '2. Review %s and set a management bind address/token.\n' "$env_file"
  printf '3. Start with: sudo systemctl enable --now ngfw-engine ngfw-api\n'
  printf '4. Verify with: sudo /usr/local/lib/ngfw/verify-m1-linux.sh and sudo /usr/local/lib/ngfw/verify-m2-linux.sh\n'
  if [[ $with_inspection -eq 1 ]]; then
    printf '5. Inspection assets are installed but sensors were not started. Start explicitly with: sudo systemctl enable --now ngfw-suricata-ids ngfw-suricata-ips ngfw-suricata-retention.timer\n'
    printf '6. Run isolated capability probes: sudo /usr/local/lib/ngfw/probe-m3-capabilities.sh --isolated --evidence-dir /tmp/ngfw-m3-probe\n'
  fi
fi

printf '\nInstaller finished. Packet-path acceptance still requires the Ubuntu VM checklists under tests/integration/.\n'
