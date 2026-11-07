#!/usr/bin/env bash
# Start the VM development UI in the background, without changing backend state.
set -Eeuo pipefail

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
for command in node curl ss flock readlink nohup; do
  command -v "$command" >/dev/null || die "Missing command: $command"
done

script=$(readlink -f -- "${BASH_SOURCE[0]}")
web_dir=$(cd -- "$(dirname -- "$script")/web" && pwd -P)
vite="$web_dir/node_modules/vite/bin/vite.js"
[[ -r "$vite" ]] || die "Web dependencies are missing. Run npm ci in $web_dir first."

port=${NGFW_WEB_PORT:-5173}
[[ "$port" =~ ^[0-9]{1,5}$ ]] || die "NGFW_WEB_PORT must be a port from 1 to 65535."
port=$((10#$port))
((port >= 1 && port <= 65535)) || die "NGFW_WEB_PORT must be a port from 1 to 65535."
host=${NGFW_WEB_HOST:-0.0.0.0}
umask 077
state_dir="${XDG_STATE_HOME:-$HOME/.local/state}/ngfw/web-$port"
mkdir -p -- "$state_dir"
log="$state_dir/vite.log"
exec 9>"$state_dir/start.lock"
flock -n 9 || die "Another web startup is in progress. Try again shortly."

ready() { curl -fsS --max-time 2 "http://127.0.0.1:$port/" >/dev/null 2>&1; }
report() {
  printf 'Web ready (PID %s, port %s).\n' "$1" "$port"
  printf 'Open http://<VM-management-IP>:%s from your browser.\n' "$port"
  if ! curl -fsS --max-time 3 "http://127.0.0.1:$port/api/v1/health" >/dev/null 2>&1; then
    printf 'The UI is running, but the API health read failed. Check ngfw-engine and ngfw-api.\n' >&2
  fi
}

listener=$(ss -H -lntp "sport = :$port")
if [[ -n "$listener" ]]; then
  pid=$(sed -nE 's/.*pid=([0-9]+).*/\1/p' <<< "$listener" | head -n 1)
  [[ -n "$pid" && $(readlink -f -- "/proc/$pid/cwd") == "$web_dir" ]] || die "Port $port belongs to another service."
  args=$(tr '\0' ' ' < "/proc/$pid/cmdline")
  [[ "$args" == *vite/bin/vite.js* ]] || die "Port $port is occupied by a non-Vite process."
  ready || die "Vite already owns port $port but is not responding yet."
  report "$pid"
  exit 0
fi

cd -- "$web_dir"
# Close the lock descriptor in the child, so later invocations can check/start.
nohup node "$vite" --host "$host" --port "$port" --strictPort \
  </dev/null >>"$log" 2>&1 9>&- &
pid=$!
printf '%s\n' "$pid" > "$state_dir/vite.pid"
for _ in {1..40}; do
  if ! kill -0 "$pid" 2>/dev/null; then
    tail -n 20 -- "$log" >&2
    die "Vite exited. See $log"
  fi
  if ready; then
    report "$pid"
    printf 'Log: %s\n' "$log"
    exit 0
  fi
  sleep 0.25
done
kill "$pid" 2>/dev/null || true
die "Vite did not become ready. See $log"
