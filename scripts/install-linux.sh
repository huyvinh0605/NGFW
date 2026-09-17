#!/usr/bin/env bash
set -Eeuo pipefail

# Install and build the M1/M2 appliance on Ubuntu 24.04.
#
# The script intentionally installs only the M1/M2 path: ngfw-engine,
# ngfw-api, iproute2, nftables and the tools used by the VM checklists. It
# does not enable the proxy, UI, ML or IDS services.

usage() {
  cat <<'EOF'
Usage: sudo bash scripts/install-linux.sh [options]

Options:
  --config FILE   Copy FILE to /etc/ngfw/lab.json when installing.
  --start         Enable and start ngfw-engine and ngfw-api after installation.
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
  apt-get install -y --no-install-recommends \
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
    procps \
    tcpdump
fi

required_commands=(go ip nft sysctl systemctl curl jq tcpdump conntrack openssl)
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
  info "Running M1/M2 unit tests"
  go test -count=1 ./...
fi

info "Building M1 services"
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$build_dir/ngfw-engine" ./cmd/ngfw-engine
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$build_dir/ngfw-api" ./cmd/ngfw-api

info "Creating service account and directories"
getent group ngfw >/dev/null 2>&1 || groupadd --system ngfw
if ! id ngfw >/dev/null 2>&1; then
  useradd --system --gid ngfw --home-dir /var/lib/ngfw --create-home --shell /usr/sbin/nologin ngfw
fi
install -d -o root -g ngfw -m 0750 /etc/ngfw
install -d -m 0755 /usr/local/lib/ngfw /usr/local/share/ngfw/examples
# The engine owns the running configuration, journal and epoch state. The API
# receives read access through the ngfw group and writes only its management
# candidate/auth data under the separate management directory.
install -d -o root -g ngfw -m 0750 /var/lib/ngfw
install -d -o ngfw -g ngfw -m 0770 /var/lib/ngfw/management /var/log/ngfw

info "Installing binaries, examples and systemd units"
install -o root -g root -m 0755 "$build_dir/ngfw-engine" /usr/local/lib/ngfw/ngfw-engine
install -o root -g root -m 0755 "$build_dir/ngfw-api" /usr/local/lib/ngfw/ngfw-api
install -o root -g root -m 0755 scripts/verify-m1-linux.sh /usr/local/lib/ngfw/verify-m1-linux.sh
install -o root -g root -m 0755 scripts/verify-m2-linux.sh /usr/local/lib/ngfw/verify-m2-linux.sh
install -o root -g root -m 0644 configs/examples/*.json /usr/local/share/ngfw/examples/
install -o root -g root -m 0644 deploy/ngfw-engine.service deploy/ngfw-api.service /etc/systemd/system/
install -o root -g root -m 0644 deploy/90-ngfw-ip-forward.conf /etc/sysctl.d/90-ngfw-ip-forward.conf
install -o root -g root -m 0644 deploy/91-ngfw-conntrack.conf /etc/sysctl.d/91-ngfw-conntrack.conf

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
  info "Starting M1 services"
  systemctl enable ngfw-engine.service ngfw-api.service
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
  "${project_root}/scripts/verify-m1-linux.sh" || die "M1 status checks failed; inspect the service journal"
  "${project_root}/scripts/verify-m2-linux.sh" || die "M2 preflight checks failed; inspect the service journal"
else
  printf '\nInstallation complete. Services were not started.\n'
  printf '1. Review %s and replace sample interface names, addresses and gateways.\n' "$config_target"
  printf '2. Review %s and set a management bind address/token.\n' "$env_file"
  printf '3. Start with: sudo systemctl enable --now ngfw-engine ngfw-api\n'
  printf '4. Verify with: sudo /usr/local/lib/ngfw/verify-m1-linux.sh and sudo /usr/local/lib/ngfw/verify-m2-linux.sh\n'
fi

printf '\nM1/M2 installer finished. Packet-path acceptance still requires the Ubuntu VM checklists in tests/integration/m1/README.md and tests/integration/m2/README.md.\n'
